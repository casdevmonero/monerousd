//! MonerousD Protocol — `src/node/replay.rs` — DB-402: ONE replay function derives every replicated field.
//!
//! Spec: docs/DB-402-STF-REPLAY-SPEC-20261027.md. BORROWED: Ethereum STF (state = f(genesis, blocks); a snap-synced
//! node installs a certified state then applies blocks through the SAME transition function), Bitcoin Core `-reindex`
//! (one `ConnectBlock` is the only writer of the UTXO set), Kaspa pruning-point IBD (install the pruning point's
//! certified state, replay every block above it).
//!
//! Every field `AUTHORITY_MANIFEST` rules `ChainDerived` has exactly ONE writer: an arm of [`Node::derive_replicated`].
//! The edit-time guard `~/.claude/hooks/replicated-writer-guard.py` refuses a new writer anywhere else; the source
//! census [`ledger::writers_outside_replay`] measures the writers still outside this module (208 at the spec's date)
//! and holds the number as a ledger that only moves down. DONE is 0 and the replica census SAME on every lane.
//!
//! The three production doors enter here: a DSYNC bundle (`handle_sync_response`, the re-anchor lane), the persisted
//! frontier at boot (`restore_from_disk`), the persisted window (`restore_snapshot`). Each arm installs its BASE — what a
//! cold replayer cannot compute — and every block above the base reaches the fields only through the one fold
//! (`fold_canonical_records`), the per-block transition every graft runs. The migration (spec §"Migration order") moves
//! each door's verbatim installer into its arm; until an arm's installer has moved, the arm calls it by name here so
//! that the door has no second entry.

use super::*;

/// The base a replay starts from: what the chain certified or this node persisted, never a local ruling.
pub enum ReplicaBase {
    /// Genesis: every field from the blocks alone (the fold).
    Chain,
    /// #29 DSYNC: the certified state at the bundle's frontier.
    CertifiedBundle(SyncBundle),
    /// Restart (#106): the O(1) frontier this node persisted, plus the fold record it was taken at.
    PersistedFrontier {
        snap: crate::persist::NodeSnapshot,
        fold: Option<crate::persist::FoldRecord>,
    },
    /// Restart (window resume): the persisted window as held, re-installed verbatim.
    PersistedVerbatim(crate::persist::NodeSnapshot),
}

/// What the door that asked for the replay learns: the arm's own verdict, never a second source of truth.
#[derive(Debug)]
pub enum ReplayOutcome {
    /// `Chain`: how many canonical records the fold applied.
    Folded(usize),
    /// `CertifiedBundle`: the adopt verdict (the bundle's proof decides, fail-closed).
    Adopt(AdoptOutcome),
    /// `PersistedFrontier`: the resume verdict.
    Resume(RestoreOutcome),
    /// `PersistedVerbatim`: whether the window was re-installed.
    Restored(bool),
}

impl Node {
    /// THE replay function (DB-402): install `base`, then every block above it reaches the replicated fields only
    /// through the fold. See the module doc for which door enters with which base.
    pub fn derive_replicated(&mut self, base: ReplicaBase) -> ReplayOutcome {
        match base {
            ReplicaBase::Chain => ReplayOutcome::Folded(self.fold_canonical_records()),
            ReplicaBase::CertifiedBundle(bundle) => ReplayOutcome::Adopt(self.derive_adopted(bundle)),
            ReplicaBase::PersistedFrontier { snap, fold } => ReplayOutcome::Resume(self.derive_resumed(snap, fold)),
            ReplicaBase::PersistedVerbatim(snap) => ReplayOutcome::Restored(self.restore_snapshot_folding(snap, true)),
        }
    }

    /// The `CertifiedBundle` arm with its verdict TYPED: a door that hands in a bundle receives an adopt verdict by the
    /// signature, so it holds no `unreachable!` for the other arms' variants (a panic path in shippable code, hole scanner).
    /// cons: none — the same call the arm made, renamed into a typed entry; nothing is written that was not before.
    pub fn derive_adopted(&mut self, bundle: SyncBundle) -> AdoptOutcome {
        self.instant_sync(bundle)
    }

    /// ⭐ DB-471 (lane stable 2026-11-01) — THE ADOPTED PREFIX, COMPLETED: a DSYNC joiner whose record lane has delivered every
    /// row below its adopted base comes to hold what a replayer holds there. Until now the prefix stayed marked "certified, not
    /// folded here" for good (`certified_prefix_len`, `da_macc_first` at the base, a partial roots-run ladder blob, no
    /// membership-accumulator rows and no slot markers below the base): the joiner replica census read six DIFFERS against
    /// the replayers on the same chain (stable/c5.log, c10.log).
    /// THE DOOR: every ordinal `1..base` has its row here and a root this node verified — the closed roots run's ladder slot
    /// (that run folded to the certified spine) or the record's own bound bytes; the membership accumulator folded from
    /// genesis over those roots must land EXACTLY on
    /// the accumulator the adopted certified state names at the base (`da_macc_first`) — so every row is the chain's record at
    /// that ordinal, short of a Poseidon2 collision — and the roots run must have closed. Anything else installs nothing and the
    /// next pass asks again. Then: the accumulator rows through the one writer every fold uses (`da_store_membership_acc`), the
    /// verified-in-slot marker per row (the leaf law `(o−1)·width`, the same marker the DB-424 restore stamps), the fold's first
    /// ordinal set to 1 from genesis as a replayer's, the certified-prefix marker retired (the slot markers now answer the
    /// prefix boundary), and the closed roots run retired with its adopted ladder blobs (an empty span reads as closed, as on
    /// a replayer; every root a blob named is now a held accumulator row).
    /// Bounded: while rows are still arriving, map reads only (the first missing row ends the pass); the fold over the prefix
    /// (ladder roots first, a record's own derive only where the ladder has none) runs when every row is held.
    /// BORROWED: Kaspa's IBD completes the pruning-point UTXO set, then holds what an archival peer holds above it.
    /// cons: none — the rows a replayer holds for the same span; one derive pass per adopt.
    pub(crate) fn complete_adopted_prefix(&mut self) {
        let base = self.certified_prefix_len;
        if base <= 1 {
            return;
        }
        // why the prefix holds back, named once per change of reason (never per fold pass)
        static HELD: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
        let held = |why: String| {
            if let Ok(mut last) = HELD.lock() {
                if *last != why {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: ordinals and counts only — no note, tag, amount, key or owner.
                    eprintln!("[db471] the adopted prefix (base {base}) waits: {why}");
                    *last = why;
                }
            }
        };
        if !self.roots_run_closed() {
            return held("the roots run is still open".to_string());
        }
        let Some((first, base_acc)) = self.da_macc_first else { return held("no adopted base accumulator".to_string()) };
        if first != base {
            return held(format!("the accumulator's first ordinal is {first}"));
        }
        // every row first (map reads only), so a prefix still filling costs no fold
        let mut addrs = Vec::with_capacity(base as usize);
        for o in 1..base {
            let Some(addr) = self.da_addr_at_ordinal(o) else { return held(format!("no row at ordinal {o}")) };
            addrs.push(addr);
        }
        let mut acc = Self::MEMBERSHIP_GENESIS_ACC;
        let mut steps = Vec::with_capacity(base as usize);
        for o in 1..base {
            // the root the closed roots run verified into the ladder (it folded to the certified spine), else the record's
            // own bound bytes; the accumulator check below binds every one of them either way
            let Some(root) = self.ladder_root_if_held(o).or_else(|| self.da_block_root_at_ordinal_derive(o)) else {
                return held(format!("no root at ordinal {o}"));
            };
            acc = usdm_decider::note_membership_air::note_membership_step_new_acc(acc, root);
            steps.push((o, acc));
        }
        if acc != base_acc {
            return held(format!("⛔ the {} prefix row(s) do not fold to the adopted base accumulator — nothing installed", base - 1));
        }
        let width = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
        for ((o, a), addr) in steps.into_iter().zip(addrs) {
            self.da_store_membership_acc(o, a);
            self.da_leafstart_mem.entry(addr).or_insert(o.saturating_sub(1).saturating_mul(width));
            // ⛔ A-F105 (lane speed5, 2026-11-19): the fold above just proved this row IS the chain's record at its ordinal
            // (genesis → the certified base accumulator, short of a Poseidon2 collision), which is what `chain-bound` means on
            // a replayer. MEASURED: without it the joiner held rows 57-78 `chain-bound false` where both replayers held them
            // `true` (replica census on e53cce79, da_mem 2595255/2595255/2595284). cons: none — one bool per proven row.
            if let Some(row) = self.da_mem.get_mut(&addr) {
                row.2 = true;
            }
        }
        self.da_macc_first = Some((1, Self::MEMBERSHIP_GENESIS_ACC));
        self.certified_prefix_len = 0;
        // the closed run is retired as a replayer holds it — no span open (`roots_run_closed` reads an empty target as
        // closed) — and every ladder blob over the prefix with it, carried or written by the run (MEASURED: releasing only
        // the carried ones left the run's own 14,143 B blob, replica census `da_ladder_mem` 2/2/14143): every root they
        // named is now a held accumulator row
        self.roots_run_spine_before = crate::spend_frontier::PoseidonSpendFrontier::new();
        self.roots_run_spine_target = crate::spend_frontier::PoseidonSpendFrontier::new();
        self.roots_run_cursor = crate::spend_frontier::PoseidonSpendFrontier::new();
        self.roots_run_closed_target = usdm_decider::poseidon2_compress::zero_digest();
        let over_prefix: Vec<u64> = self.da_ladder_mem.keys().copied().filter(|sp| sp.saturating_mul(Self::DA_LADDER_SPAN) < base).collect();
        for sp in over_prefix {
            self.da_ladder_mem.remove(&sp);
            self.da_ladder_adopted.remove(&sp);
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: an ordinal count only.
        eprintln!("[db471] the adopted prefix completed: {} row(s) below the base now hold their accumulator and slot marker", base - 1);
    }

    /// A record the fold stripped bare, back as it stood before the restart: held, no notes, its own cover key, so its root derives
    /// as it did live and no peer is asked for bytes that no longer exist. Only such a row saves a key beside a coordinate (a row
    /// whose bytes are merely wanted is not held and has none), so a wanted record stays wanted.
    /// cons: none — the row the node already held; bounded with the row maps by the ladder span.
    pub(super) fn install_stripped_row(&mut self, rid: u64, key: crate::cover::CoverKey, bound: bool) {
        self.da_mem.entry(rid).or_insert((Vec::new(), Vec::new(), bound, key));
    }

    /// Replace one record's tags with the list a row change left (`fold::tags_after_strip` / `tags_after_restore`): the
    /// strip and its rewind are the only callers. An empty list leaves the record with no tag (every tagged note left it).
    /// MOVED HERE VERBATIM from `node/da.rs` (lane goods, audit 2026-11-12): `da_tags_mem` is a ChainDerived field and
    /// this module is where its writers live. The writer census read 178 against a ledger of 177 on main: this function
    /// (two writes, landed 2026-11-09) and [`Self::install_coordinate_row`] (three) had entered outside the module while
    /// two fields leaving the class hid four of the five.
    /// O1-FOOTPRINT-REVIEWED: no new store. The map is `da_store_tags`'s own (`node/da.rs`), released with its rows by the
    /// ladder span; this replaces or removes ONE existing record's entry and never adds a record.
    /// cons: none — the same two writes at the same two call sites; no byte, order or bound changes.
    pub(super) fn da_tags_replace(&mut self, seq: u64, tags: Vec<(u8, [u8; crate::oli::K_BYTES])>) {
        if tags.is_empty() {
            self.da_tags_mem.remove(&seq);
        } else {
            self.da_tags_mem.insert(seq, tags);
        }
    }

    /// v63: a real record's ordinal row whose bytes this node had not yet fetched when it stopped, back as its COORDINATE
    /// only (the bytes stay wanted by id; `regenerate_idle_record` answers nothing for a block that does not declare
    /// itself idle). A row whose ordinal another record already holds here installs nothing.
    /// MOVED HERE VERBATIM from the persisted window's restore (`restore_snapshot_folding`), for the reason
    /// [`Self::da_tags_replace`] gives: the three writes below are of ChainDerived fields.
    /// O1-FOOTPRINT-REVIEWED: no new store. The ordinal maps are `da_store_ordinal`'s own (`node/da.rs`); this re-installs
    /// rows the node's own snapshot held when it stopped (`snap.coordinate_rows`), bounded with the row maps by the
    /// ladder span.
    /// cons: none — the same writes for the same rows.
    pub(super) fn install_coordinate_row(&mut self, rid: u64, ord: u64) {
        if ord != u64::MAX && !self.da_ord_rev_mem.contains_key(&ord) {
            self.da_ord_mem.entry(rid).or_insert(ord);
            self.da_ord_rev_mem.insert(ord, rid);
            self.da_ord_top = self.da_ord_top.max(ord);
        }
    }

    /// The `PersistedFrontier` arm with its verdict typed, for the same reason as [`Self::derive_adopted`]. cons: none.
    pub fn derive_resumed(&mut self, snap: crate::persist::NodeSnapshot, fold: Option<crate::persist::FoldRecord>) -> RestoreOutcome {
        self.resume_from_checkpoint(snap, fold)
    }
}

/// The writer ledger: the guard's own regex over the whole non-test source, counted per function.
#[cfg(test)]
pub(crate) mod ledger {
    use std::collections::BTreeMap;

    /// Writes of a manifest-ChainDerived field outside this module, as measured at the spec's date (2026-10-27,
    /// 41 fields). This number only moves DOWN: a migration batch re-records it; a new writer is refused by the guard.
    /// Re-recorded 2026-10-29 (lane funds-tok): 179 → 177, measured on main @ 05daa25 and on the lane (f290-C4).
    /// Re-recorded 2026-11-12 (lane goods, audit): 177 → 173. Main @ ffd3e074 measured 178, one ABOVE the ledger: five
    /// writes had entered outside this module since (`da_tags_replace`, two, 2026-11-09; the restore's coordinate rows,
    /// three) while two fields leaving the ChainDerived class (`dsol_registry`, `served_fold_count`) took four away.
    /// The five are moved into this module verbatim; 173 is 177 less the four, measured on the lane.
    pub(crate) const WRITERS_OUTSIDE_REPLAY_LEDGER: usize = 173;

    const METHODS: &[&str] = &[
        "insert", "push", "push_back", "remove", "clear", "extend", "retain", "truncate", "drain", "pop", "append", "swap",
        "take", "replace", "get_mut", "entry", "iter_mut", "sort", "dedup",
    ];
    const RECEIVERS: &[&str] = &["self", "node", "n", "this", "st", "state"];

    fn exempt(path: &str) -> bool {
        path.contains("/harness/")
            || path.ends_with("/node/replay.rs")
            || path.ends_with("test_support.rs")
            || path.ends_with("pins.rs")
            || path.ends_with("tests.rs")
            || path.ends_with("_tests.rs")
            || path.ends_with("authority.rs")
    }

    fn is_ident(c: u8) -> bool {
        c.is_ascii_alphanumeric() || c == b'_'
    }
    fn ident_len(b: &[u8], from: usize) -> usize {
        b[from..].iter().take_while(|c| is_ident(**c)).count()
    }
    fn skip_ws(b: &[u8], mut i: usize) -> usize {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    }

    /// The ChainDerived fields, read off the manifest SOURCE (the guard reads the same text; no type dependency).
    pub(crate) fn chain_derived_fields() -> Vec<String> {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/harness/fuzz/authority.rs"))
            .expect("the authority manifest is readable");
        let mut out: Vec<String> = src
            .lines()
            .filter(|l| l.contains("Authority::ChainDerived"))
            .filter_map(|l| {
                let a = l.find('"')? + 1;
                let z = a + l[a..].find('"')?;
                let name = &l[a..z];
                (!name.is_empty() && name.bytes().all(is_ident)).then(|| name.to_string())
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// The writes of a ChainDerived field on one line of code (comments already stripped): the guard's regex.
    pub(crate) fn writes_in_line(code: &str, fields: &[String]) -> Vec<String> {
        let b = code.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] != b'.' {
                i += 1;
                continue;
            }
            let mut j = i;
            while j > 0 && b[j - 1].is_ascii_whitespace() {
                j -= 1;
            }
            let mut k = j;
            while k > 0 && is_ident(b[k - 1]) {
                k -= 1;
            }
            if !RECEIVERS.contains(&&code[k..j]) {
                i += 1;
                continue;
            }
            let p = skip_ws(b, i + 1);
            let q = p + ident_len(b, p);
            if q == p || !fields.iter().any(|f| f == &code[p..q]) {
                i += 1;
                continue;
            }
            let r = skip_ws(b, q);
            let rest = &b[r..];
            let hit = (rest.first() == Some(&b'=') && rest.get(1) != Some(&b'='))
                || rest.starts_with(b"+=")
                || rest.starts_with(b"-=")
                || (rest.first() == Some(&b'.') && {
                    let s = skip_ws(b, r + 1);
                    let e = s + ident_len(b, s);
                    METHODS.contains(&&code[s..e]) && b.get(skip_ws(b, e)) == Some(&b'(')
                });
            if hit {
                out.push(code[p..q].to_string());
            }
            i = q;
        }
        out
    }

    fn fn_name(line: &str) -> Option<&str> {
        let t = line.trim_start();
        let t = match t.strip_prefix("pub") {
            Some(r) => {
                let r = r.trim_start();
                if r.starts_with('(') {
                    r.find(')').map(|p| r[p + 1..].trim_start()).unwrap_or(r)
                } else {
                    r
                }
            }
            None => t,
        };
        let r = t.strip_prefix("fn ")?;
        let n = ident_len(r.as_bytes(), 0);
        (n > 0).then(|| &r[..n])
    }

    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }

    /// Every write of a ChainDerived field outside `src/node/replay.rs`, per `file:function`, and the total.
    pub(crate) fn writers_outside_replay() -> (usize, BTreeMap<String, usize>) {
        let fields = chain_derived_fields();
        assert!(fields.len() >= 30, "CALIBRATION: the manifest names the ChainDerived fields ({})", fields.len());
        let mut files = Vec::new();
        walk(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")), &mut files);
        files.sort();
        let mut by_fn: BTreeMap<String, usize> = BTreeMap::new();
        let mut total = 0usize;
        for path in files {
            let ps = path.to_string_lossy().to_string();
            if exempt(&ps) {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&path) else { continue };
            let base = path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
            let mut cur = "?".to_string();
            for line in src.lines() {
                if let Some(f) = fn_name(line) {
                    cur = f.to_string();
                }
                let code = line.split("//").next().unwrap_or("");
                let n = writes_in_line(code, &fields).len();
                if n > 0 {
                    total += n;
                    *by_fn.entry(format!("{base}:{cur}")).or_insert(0) += n;
                }
            }
        }
        (total, by_fn)
    }
}
