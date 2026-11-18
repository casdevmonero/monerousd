// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ DB-223 Q2 §12d H — THE WALLET'S CATCH-UP CLIENT for the level-major window tables.
//!
//! A wallet whose member witness book fell behind the path-refresh stream's reach (offline past it) is missing the
//! roots of every window that completed in the gap. For the HIGH levels (`≥ window_index::HIGH_LEVEL`) those roots live
//! in one level-major table per level, indexed by window number, served by every node (`/window_index_high_*`).
//!
//! THE RULE THAT KEEPS IT PRIVATE (§12, §12d): a catch-up asks EVERY high level, for EVERY note, in one shape, whatever
//! that note needs:
//!   * a WHOLE-mode table (a public function of its length, `window_index::high_mode`) is fetched outright, once per
//!     catch-up — every catching-up wallet fetches every whole table, so fetching one names nothing;
//!   * a PIR-mode table's hint is fetched once per catch-up, and each note asks it ONE SimplePIR query on the OLI
//!     layout — its own sibling window's column, or a uniform dummy column where it needs nothing at that level — so
//!     the table names are constant and the cell is hidden. No block shard is ever named here (levels below
//!     `HIGH_LEVEL` are the note's own shard's).
//!
//! SHAPE: one [`CatchUp`] per catch-up holds at most one table or hint per high LEVEL (a fixed count, `SPEND_TREE_DEPTH −
//! HIGH_LEVEL`); [`CatchUp::note`] does O(levels) work for one note and returns at most one root per level.
//!
//! TRUST: nothing served is believed. A recovered root is only a capture: the book takes it only at the note's own
//! sibling window, and a path that does not refold to the ring root the node's own ring holds is refused at the carrier.
use usdmd_node::fixed::FixedBytes;
use std::collections::BTreeMap;
use usdmd_node::spend_frontier::Digest4;
use usdmd_node::window_index::{root_in_column, ROOTS_PER_COL};

/// One high level as `/window_index_high_params` describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HighLevel {
    pub level: usize,
    /// Roots the table holds (its public length).
    pub len: usize,
    /// PIR mode (else WHOLE), the public function of `len` the node applied.
    pub pir: bool,
    /// Columns of the table in the OLI layout (`ROOTS_PER_COL` roots per `S_ROWS`-byte column).
    pub cols: usize,
}

/// `/window_index_high_params`: the PIR seed, the wave bound, and every high level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HighParams {
    pub seed: [u8; 32],
    pub wave_queries: usize,
    pub levels: Vec<HighLevel>,
}

/// ⛔⛔ DB-405 — A PIR HINT AND THE TABLE VERSION IT WAS COMPUTED OVER. A SimplePIR answer decodes only against the hint of
/// the SAME table (answer − hint·s), and a node folds on between a wallet's hint ask and its answer asks, so every answer
/// ask echoes this: the node answers over the table AS OF `version` and refuses (`HINT_STALE`) when that table's digest is
/// not `digest` (a rewind rewrote a covered cell). MEASURED sim-20261006-235327 T1.7: after node 0's restart (its fold
/// replaying) W1's note read "missing [] · refolds false" on 14 sends over 832 simulated s — a level filled with a root
/// decoded against a newer table's answer, and a captured level is filled only once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hinted {
    /// The table version the node computed the hint over: records folded (a shard) or roots covered (a high level).
    pub version: u64,
    /// `window_index::table_digest` of that table.
    pub digest: [u8; 32],
    /// The PIR columns the hint covers (every query is `cols × 4` bytes).
    pub cols: usize,
    /// The hint bytes (`oli::recover_bucket`'s shape).
    pub hint: Vec<u8>,
}

/// The four read-only doors a catch-up speaks — over HTTP in production, in-process in a pin, ONE client either way.
pub trait HighIndex {
    fn params(&self) -> Result<HighParams, String>;
    /// A WHOLE-mode table's bytes (column-major, `S_ROWS`-byte columns).
    fn table(&self, level: usize) -> Result<Vec<u8>, String>;
    /// A PIR-mode table's hint and the table version it covers.
    fn hint(&self, level: usize) -> Result<Hinted, String>;
    /// Answers to `queries` (each `h.cols × 4` bytes, at most `wave_queries` of them) over the table `h` was computed on,
    /// one `S_ROWS × 4`-byte answer each.
    fn answer(&self, level: usize, h: &Hinted, queries: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String>;
}

/// ⭐⭐ ONE CATCH-UP: the params, and every whole table and PIR hint fetched ONCE (keyed by level — a fixed count), then
/// [`Self::note`] per note.
pub struct CatchUp<'s, S: HighIndex> {
    src: &'s S,
    params: HighParams,
    tables: BTreeMap<usize, Vec<u8>>,
    hints: BTreeMap<usize, Hinted>,
}

impl<'s, S: HighIndex> CatchUp<'s, S> {
    /// Read the params and fetch EVERY high level's whole table or PIR hint, whatever any note needs (the constant set of
    /// names). A level nothing has completed at yet (`len == 0`) has nothing to fetch, for any wallet.
    /// cons: at 10 years ≈ 3.7 MB once per catch-up (6 PIR hints of 512 KB + ≈ 615 KB of whole tables), at 1 year
    /// ≈ 2 MB (the node's `q2_catch_up_pir_cost_at_1_and_10_years`); constant in the wallet's history.
    pub fn new(src: &'s S) -> Result<Self, String> {
        let params = src.params()?;
        let mut tables = BTreeMap::new();
        let mut hints = BTreeMap::new();
        for lv in &params.levels {
            if lv.len == 0 {
                continue;
            }
            if lv.pir {
                hints.insert(lv.level, src.hint(lv.level)?);
            } else {
                tables.insert(lv.level, src.table(lv.level)?);
            }
        }
        Ok(Self { src, params, tables, hints })
    }

    /// ⭐ ONE NOTE's catch-up: `wants` are its `(level, window)` needs at the high levels (its own sibling, at most one
    /// per level). EVERY PIR level is asked exactly one query — the wanted column or a uniform dummy — so the node sees
    /// the same asks whatever the note needs. `fresh` supplies 32 fresh CSPRNG bytes per call. Returns the roots
    /// recovered for the wants, `(level, window, root)`, at most one per level — a capture, never authority.
    /// cons: one query per PIR level (≈ 1.21 MB per note at 10 years); O(levels), no term in history.
    pub fn note(
        &self,
        wants: &[(usize, u64)],
        mut fresh: impl FnMut() -> [u8; 32],
    ) -> Result<Vec<(usize, u64, Digest4)>, String> {
        let s_rows = usdmd_node::oli::S_ROWS;
        let mut out: Vec<(usize, u64, Digest4)> = Vec::new();
        for lv in &self.params.levels {
            let want = wants.iter().find(|(l, _)| *l == lv.level).map(|(_, w)| *w);
            if let Some(table) = self.tables.get(&lv.level) {
                if let Some(w) = want {
                    let col = usize::try_from(w).map_err(|_| "a window past the address space".to_string())? / ROOTS_PER_COL;
                    if let Some(root) = table.get(col * s_rows..(col + 1) * s_rows).and_then(|c| root_in_column(c, w as usize)) {
                        out.push((lv.level, w, root));
                    }
                }
                continue;
            }
            let Some(hinted) = self.hints.get(&lv.level) else {
                continue; // nothing completed at this level anywhere: nothing any wallet can ask
            };
            let (cols, hint) = (&hinted.cols, &hinted.hint);
            if *cols == 0 {
                continue;
            }
            // The wanted column when this hint covers it; otherwise a uniform dummy (a window past the covered columns
            // is asked at the next catch-up, once covered).
            let covered = want.filter(|w| (*w as usize / ROOTS_PER_COL) < *cols);
            let target = match covered {
                Some(w) => w as usize / ROOTS_PER_COL,
                None => {
                    let r = fresh();
                    (u64::from_le_bytes(r[..8].fixed()) % *cols as u64) as usize
                }
            };
            let (query, secret) = usdmd_node::oli::build_query(*cols, &self.params.seed, target, &fresh());
            let answers = self.src.answer(lv.level, hinted, std::slice::from_ref(&query))?;
            let answer = answers.first().ok_or_else(|| format!("level {}: no answer", lv.level))?;
            if let Some(w) = covered {
                let column = usdmd_node::oli::recover_bucket(answer, hint, &secret, 0)
                    .ok_or_else(|| format!("level {}: the answer did not decode", lv.level))?;
                if let Some(root) = root_in_column(&column, w as usize) {
                    out.push((lv.level, w, root));
                }
            }
        }
        Ok(out)
    }
}

/// The production [`HighIndex`]: the node's four read-only POST doors.
pub struct HttpHighIndex<'a> {
    pub agent: &'a ureq::Agent,
    pub base: String,
}

impl HttpHighIndex<'_> {
    fn post(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value, String> {
        let v: serde_json::Value = self
            .agent
            .post(&format!("{}{path}", self.base))
            .send_json(body)
            .map_err(|e| format!("{path}: {e}"))?
            .into_json()
            .map_err(|e| format!("{path}: {e}"))?;
        if v.get("status").and_then(|s| s.as_str()) == Some("OK") {
            Ok(v)
        } else {
            // The node's refusal, whole (e.g. TABLE_NOT_HELD: ask another holder) — named, never read as empty.
            Err(format!("{path}: the node refused: {v}"))
        }
    }
}

fn hex_field(v: &serde_json::Value, k: &str) -> Result<Vec<u8>, String> {
    v.get(k).and_then(|x| x.as_str()).and_then(|h| hex::decode(h).ok()).ok_or_else(|| format!("no {k}"))
}

/// A hint door's answer — the hint and the table version it names (DB-405). `cols` for a high level; a shard's is fixed.
fn hinted_from(v: &serde_json::Value, cols: usize) -> Result<Hinted, String> {
    let version = v.get("version").and_then(serde_json::Value::as_u64).ok_or("no version")?;
    let digest: [u8; 32] = hex_field(v, "digest_hex")?.try_into().map_err(|_| "digest_hex is not 32 bytes")?;
    Ok(Hinted { version, digest, cols, hint: hex_field(v, "hint_hex")? })
}

impl HighIndex for HttpHighIndex<'_> {
    fn params(&self) -> Result<HighParams, String> {
        let v = self.post("/window_index_high_params", serde_json::json!({}))?;
        let seed: [u8; 32] = hex_field(&v, "pir_seed_hex")?.try_into().map_err(|_| "pir_seed_hex is not 32 bytes")?;
        let wave_queries = v.get("wave_queries").and_then(|x| x.as_u64()).ok_or("no wave_queries")? as usize;
        let mut levels = Vec::new();
        for l in v.get("levels").and_then(|x| x.as_array()).ok_or("no levels")? {
            let num = |k: &str| l.get(k).and_then(|x| x.as_u64()).ok_or_else(|| format!("a level without {k}"));
            levels.push(HighLevel {
                level: num("level")? as usize,
                len: num("len")? as usize,
                pir: l.get("mode").and_then(|m| m.as_str()) == Some("pir"),
                cols: num("cols")? as usize,
            });
        }
        Ok(HighParams { seed, wave_queries, levels })
    }

    fn table(&self, level: usize) -> Result<Vec<u8>, String> {
        hex_field(&self.post("/window_index_high_table", serde_json::json!({ "level": level }))?, "table_hex")
    }

    fn hint(&self, level: usize) -> Result<Hinted, String> {
        let v = self.post("/window_index_high_hint", serde_json::json!({ "level": level }))?;
        let cols = v.get("cols").and_then(|x| x.as_u64()).ok_or("no cols")? as usize;
        hinted_from(&v, cols)
    }

    fn answer(&self, level: usize, h: &Hinted, queries: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        let v = self.post(
            "/window_index_high_answer",
            serde_json::json!({
                "level": level,
                "cols": h.cols,
                "version": h.version,
                "digest_hex": hex::encode(h.digest),
                "queries_hex": hex::encode(queries.concat())
            }),
        )?;
        let bytes = hex_field(&v, "answers_hex")?;
        let each = usdmd_node::oli::S_ROWS * 4;
        if bytes.len() != each * queries.len() {
            return Err(format!("level {level}: {} answer bytes for {} queries", bytes.len(), queries.len()));
        }
        Ok(bytes.chunks(each).map(<[u8]>::to_vec).collect())
    }
}

/// ⭐⭐ THE LOW HALF OF THE CATCH-UP — a held note's own-shard levels (`RECORD_LEVEL .. HIGH_LEVEL`) from the node's
/// shard tables, each fetched WHOLE (`/window_index_params` + `/window_index_table`, DB-413).
///
/// MEASURED 2026-10-06 (simulator `sim-20261006-030645`, T1.2): a note the OLI lookup found — located, decapped, owned —
/// read "confirming" for 320 s, because its levels 8..18 had completed before the stream's reach and nothing else carries
/// them; every seed restore is the same case for EVERY note.
///
/// THE RULE THAT KEEPS IT PRIVATE (§12, the low half): a low window names its shard, so a catch-up fetches EVERY shard
/// the node holds (the constant name set `held_shards`), each whole, and reads every note's cells LOCALLY — the node sees
/// the identical asks whatever any note needs, whether any does, and however many notes this wallet holds.
/// ⛔⛔ DB-413 — WHY WHOLE, NOT PIR: a shard table is `SHARD_COLS × S_ROWS` = 256 KB, half of the 512 KB SimplePIR hint the
/// PIR shape fetched for it first, so the whole table is fewer bytes than the hint alone (the §12d rule the level-major
/// tables already follow). The PIR shape then asked `FIXED_LEVELS` queries (8 KB up each) PER NOTE, so its cost grew
/// with the notes and its query count told the node how many of them were catching up. MEASURED (sim-20261007-105238,
/// T1.7 seed 0x1): after node 0's restart W1 held 98+ restored notes wanting low windows, more than the 64 the wallet
/// runs inline, so the catch-up went to a detached thread a one-command process never waited for — its whole 2.3 B read
/// "confirming" on every call for 1,200 simulated s. Whole tables cost one fetch per held shard, independent of notes.
/// TRUST: nothing served is believed — a read root is only a capture at the note's own sibling window, and the carrier's
/// refold to the ring root the node's own ring names decides.
/// cons: per catch-up one 256 KB table per held shard (a shard is 2,048 records: 1 today, ≈ 1 per 68 minutes at the
/// 2 blocks/s target) — half the bytes of the PIR shape's hints, and nothing per note.
pub trait LowIndex {
    /// The shards the node serves whole.
    fn low_params(&self) -> Result<Vec<u64>, String>;
    /// A shard's whole table (`SHARD_COLS × S_ROWS` bytes, `WindowIndex::table`'s layout).
    fn low_table(&self, shard: u64) -> Result<Vec<u8>, String>;
}

/// One low catch-up: every held shard's whole table, fetched ONCE; then [`Self::note`] per note, a local read.
pub struct LowCatchUp {
    tables: BTreeMap<u64, Vec<u8>>,
}

impl LowCatchUp {
    pub fn new<S: LowIndex>(src: &S) -> Result<Self, String> {
        let want = usdmd_node::window_index::SHARD_COLS * usdmd_node::oli::S_ROWS;
        let mut tables = BTreeMap::new();
        for s in src.low_params()? {
            let t = src.low_table(s)?;
            if t.len() != want {
                return Err(format!("shard {s}: a table of {} bytes, not {want}", t.len()));
            }
            tables.insert(s, t);
        }
        Ok(Self { tables })
    }

    /// The shards this catch-up holds whole.
    #[must_use]
    pub fn shards(&self) -> Vec<u64> {
        self.tables.keys().copied().collect()
    }

    /// ONE note: `wants` are its `(level, window)` needs at the low levels. Read locally from the fetched tables — asks
    /// the node nothing. Returns the roots read, `(level, window, root)` — a capture, never authority.
    #[must_use]
    pub fn note(&self, wants: &[(usize, u64)]) -> Vec<(usize, u64, Digest4)> {
        let rows = usdmd_node::oli::S_ROWS;
        wants
            .iter()
            .filter_map(|(l, w)| {
                let (shard, cell) = usdmd_node::window_index::locate(*l, *w)?;
                let t = self.tables.get(&shard)?;
                let col = cell / ROOTS_PER_COL;
                root_in_column(t.get(col * rows..(col + 1) * rows)?, cell).map(|r| (*l, *w, r))
            })
            .collect()
    }
}

impl LowIndex for HttpHighIndex<'_> {
    fn low_params(&self) -> Result<Vec<u64>, String> {
        let v = self.post("/window_index_params", serde_json::json!({}))?;
        v.get("held_shards")
            .and_then(|x| x.as_array())
            .ok_or("no held_shards")?
            .iter()
            .map(|s| s.as_u64().ok_or_else(|| "a held shard is not a number".to_string()))
            .collect()
    }

    fn low_table(&self, shard: u64) -> Result<Vec<u8>, String> {
        hex_field(&self.post("/window_index_table", serde_json::json!({ "shard": shard }))?, "table_hex")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use usdmd_node::window_index::{self, WindowIndex, HIGH_LEVEL, WHOLE_MAX_ROOTS};

    /// The SERVER party: the node library's own level-major index and doors, in process, recording what was asked.
    struct NodeSide {
        index: WindowIndex,
        seed: [u8; 32],
        asked: RefCell<Vec<(&'static str, usize)>>,
    }

    impl HighIndex for NodeSide {
        fn params(&self) -> Result<HighParams, String> {
            let levels = (HIGH_LEVEL..usdmd_node::spend_frontier::SPEND_TREE_DEPTH)
                .map(|l| {
                    let len = self.index.high_len(l);
                    HighLevel {
                        level: l,
                        len,
                        pir: window_index::high_mode(len) == window_index::HighMode::Pir,
                        cols: window_index::high_cols(len),
                    }
                })
                .collect();
            Ok(HighParams { seed: self.seed, wave_queries: usdmd_node::oli::WAVE_QUERIES, levels })
        }
        fn table(&self, level: usize) -> Result<Vec<u8>, String> {
            self.asked.borrow_mut().push(("table", level));
            self.index.high_table(level).ok_or_else(|| "TABLE_NOT_HELD".to_string())
        }
        fn hint(&self, level: usize) -> Result<Hinted, String> {
            self.asked.borrow_mut().push(("hint", level));
            let t = self.index.high_table(level).ok_or("TABLE_NOT_HELD")?;
            let h = window_index::extend_high_hint(None, &t, &self.seed);
            Ok(Hinted {
                version: self.index.high_len(level) as u64,
                digest: window_index::table_digest(&t),
                cols: h.cols,
                hint: window_index::high_hint_bytes(&h),
            })
        }
        fn answer(&self, level: usize, h: &Hinted, queries: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
            self.asked.borrow_mut().push(("query", level));
            let t = self.index.high_table_at(level, h.version as usize).ok_or("TABLE_NOT_HELD")?;
            if window_index::table_digest(&t) != h.digest {
                return Err("HINT_STALE".to_string());
            }
            assert!(queries.iter().all(|q| q.len() == h.cols * 4), "every query is cols × 4 bytes");
            window_index::high_answer(&t, queries).ok_or_else(|| "BAD_REQUEST:QUERY_SHAPE".to_string())
        }
    }

    fn root(level: usize, w: u64) -> Digest4 {
        usdm_decider::poseidon2_compress::lanes_of(&[level as u64, w, 0xCA7C])
    }

    /// The SERVER party for the low half: the node library's own `WindowIndex::table` (what `/window_index_table` runs),
    /// recording which shards were asked.
    struct ShardSide {
        index: WindowIndex,
        asked: RefCell<Vec<u64>>,
    }

    impl LowIndex for ShardSide {
        fn low_params(&self) -> Result<Vec<u64>, String> {
            Ok(self.index.held_shards().collect())
        }
        fn low_table(&self, shard: u64) -> Result<Vec<u8>, String> {
            self.asked.borrow_mut().push(shard);
            self.index.table(shard, u64::MAX).ok_or_else(|| "SHARD_NOT_HELD".to_string()) // every fixture window is folded
        }
    }

    /// ⭐ THE LOW CATCH-UP, CLIENT AGAINST THE NODE'S OWN SHARD TABLES, AND ITS CONSTANT SHAPE (DB-413). The node holds
    /// two shards; a note in shard 1 needs four own-shard windows; the client recovers EXACTLY the recorded roots. A
    /// catch-up for a note in shard 0 needing one window, for a note needing nothing, or for 300 notes asks the node the
    /// IDENTICAL sequence (every held shard once, whole). TAMPER: a table with one flipped byte in a wanted cell never
    /// yields that cell's recorded root (the carrier's refold refuses whatever it reads).
    /// ROOT-LAYER: the roots are PRODUCED by the node's fold into its `WindowIndex`; this is the one wallet client that reads
    ///   that producer's shard tables — nothing is defaulted or guessed.
    /// MEASURED: before — sim-20261007-105238 T1.7 (seed 0x1): 98+ wanting notes pushed the per-note PIR catch-up onto a
    ///   detached thread a one-command process never joined, and W1's 2.3 B read "confirming" for ever; after — this pin
    ///   (the shape no longer depends on the note count) and the simulator journey decide.
    /// MUST-STAY-GREEN: `q2_h_the_catch_up_recovers_the_nodes_roots_and_asks_every_level_the_same_way`; the node's
    ///   `db413_the_window_index_table_route_serves_the_nodes_own_shard_table_whole` (the route's half).
    /// TWO-PARTY-REVIEWED: the SERVER is the node library's own `WindowIndex::table` (the code the route runs); the CLIENT
    /// is this wallet module; the pin asserts they AGREE on every root.
    #[test]
    fn low_catch_up_recovers_the_nodes_own_shard_roots_and_asks_every_shard_the_same_way() {
        use window_index::{locate, RECORD_LEVEL, SHARD_BLOCKS};
        let mut index = WindowIndex::new();
        // every low window of shards 0 and 1 (records 0 .. 2·SHARD_BLOCKS)
        for shard in 0..2u64 {
            for (l, w) in window_index::windows_in_shard(shard) {
                assert!(index.record(l, w, root(l, w)), "a low window is recorded");
            }
        }
        let node = ShardSide { index, asked: RefCell::new(Vec::new()) };
        // a note in record SHARD_BLOCKS + 5 (shard 1): its own-shard sibling windows at four levels
        let record = SHARD_BLOCKS + 5;
        let wants: Vec<(usize, u64)> = [RECORD_LEVEL, RECORD_LEVEL + 1, RECORD_LEVEL + 3, RECORD_LEVEL + 6]
            .iter()
            .map(|&l| (l, (record >> (l - RECORD_LEVEL)) ^ 1))
            .collect();
        assert!(wants.iter().all(|(l, w)| locate(*l, *w).map(|(s, _)| s) == Some(1)), "PRECONDITION: all in shard 1");
        let run = |notes: &[Vec<(usize, u64)>]| {
            node.asked.borrow_mut().clear();
            let cu = LowCatchUp::new(&node).expect("the low catch-up opens");
            let mut got: Vec<(usize, u64, Digest4)> = notes.iter().flat_map(|w| cu.note(w)).collect();
            got.sort();
            (got, node.asked.borrow().clone())
        };
        let (got, shape_a) = run(&[wants.clone()]);
        let mut want_roots: Vec<(usize, u64, Digest4)> = wants.iter().map(|(l, w)| (*l, *w, root(*l, *w))).collect();
        want_roots.sort();
        assert_eq!(got, want_roots, "⛔ the wallet did not recover the own-shard roots the node recorded");
        let (_, shape_b) = run(&[vec![(RECORD_LEVEL, 7)]]);
        let (none, shape_c) = run(&[vec![]]);
        let many: Vec<Vec<(usize, u64)>> = (0..300u64).map(|r| vec![(RECORD_LEVEL, r ^ 1)]).collect();
        let (got_many, shape_d) = run(&many);
        assert!(none.is_empty(), "a note needing nothing recovers nothing");
        assert_eq!(got_many.len(), 300, "every one of 300 notes reads its window locally");
        assert_eq!(shape_a, vec![0, 1], "every held shard is fetched once, whole: {shape_a:?}");
        assert_eq!(shape_b, shape_a, "⛔ what the node sees depends on which shard or windows the wallet needs");
        assert_eq!(shape_c, shape_a, "⛔ what the node sees depends on whether the wallet needs anything");
        assert_eq!(shape_d, shape_a, "⛔ DB-413: what the node sees depends on how many notes the wallet catches up");
        struct Tampered<'a>(&'a ShardSide, usize);
        impl LowIndex for Tampered<'_> {
            fn low_params(&self) -> Result<Vec<u64>, String> {
                self.0.low_params()
            }
            fn low_table(&self, shard: u64) -> Result<Vec<u8>, String> {
                let mut t = self.0.low_table(shard)?;
                if shard == 1 {
                    t[self.1 * window_index::ROOT_BYTES + 3] ^= 0x80;
                }
                Ok(t)
            }
        }
        let (l0, w0) = wants[0];
        let cell = locate(l0, w0).expect("a low window").1;
        let bad = LowCatchUp::new(&Tampered(&node, cell)).expect("opens").note(&wants[..1]);
        assert!(!bad.contains(&(l0, w0, root(l0, w0))), "CALIBRATION: a tampered cell must not read as the recorded root");
        let short = LowCatchUp::new(&Short(&node));
        struct Short<'a>(&'a ShardSide);
        impl LowIndex for Short<'_> {
            fn low_params(&self) -> Result<Vec<u64>, String> {
                self.0.low_params()
            }
            fn low_table(&self, shard: u64) -> Result<Vec<u8>, String> {
                let mut t = self.0.low_table(shard)?;
                t.pop();
                Ok(t)
            }
        }
        assert!(short.is_err(), "⛔ a table of the wrong shape was read");
    }

    /// ⛔⛔ DB-405 (whole-table form) — A TABLE FETCHED BEFORE A FOLD READS EVERY ROOT THAT COMPLETED BEFORE IT, and a later
    /// fold cannot move a cell already read: the node cuts the table at its folded version (a cell is in it once its pair
    /// merged), the wallet reads every cell from the ONE fetch, so there is no hint/answer pair a fold can fall between.
    /// MEASURED sim-20261006-235327 T1.7 (the PIR shape): 14 sends refused "the refreshed path does not refold" after node
    /// 0's restart — a level decoded against a newer table's answer. CALIBRATION: the fold changed the shard's table.
    /// TWO-PARTY-REVIEWED: the SERVER is the node library's own `WindowIndex::table` (pinned through the dispatcher by
    /// `db413_the_window_index_table_route_serves_the_nodes_own_shard_table_whole`); the CLIENT is this module.
    #[test]
    fn db405_the_low_catch_up_over_a_node_folding_after_the_fetch_reads_the_recorded_roots() {
        use window_index::{completing_block, RECORD_LEVEL};
        struct Folding {
            index: RefCell<WindowIndex>,
        }
        impl LowIndex for Folding {
            fn low_params(&self) -> Result<Vec<u64>, String> {
                Ok(vec![0])
            }
            fn low_table(&self, shard: u64) -> Result<Vec<u8>, String> {
                let t = self.index.borrow().table(shard, 40).ok_or("SHARD_NOT_HELD")?;
                // the node folds on right after the wallet's fetch: eight more records' windows land in the same shard
                let mut idx = self.index.borrow_mut();
                for (l, w) in window_index::windows_in_shard(shard) {
                    if completing_block(l, w).is_some_and(|b| (40..48).contains(&b)) {
                        idx.record(l, w, root(l, w));
                    }
                }
                Ok(t)
            }
        }
        let mut index = WindowIndex::new();
        for (l, w) in window_index::windows_in_shard(0) {
            if completing_block(l, w).is_some_and(|b| b < 40) {
                index.record(l, w, root(l, w));
            }
        }
        let node = Folding { index: RefCell::new(index) };
        // a note in record 5: its sibling windows at the levels whose pair merged below block 40
        let wants: Vec<(usize, u64)> = (RECORD_LEVEL..RECORD_LEVEL + 5)
            .map(|l| (l, (5u64 >> (l - RECORD_LEVEL)) ^ 1))
            .filter(|(l, w)| completing_block(*l, *w | 1).is_some_and(|b| b < 40))
            .collect();
        assert!(wants.len() >= 4, "PRECONDITION: the note wants several completed own-shard windows: {wants:?}");
        let before = node.index.borrow().table(0, 40);
        let cu = LowCatchUp::new(&node).expect("the low catch-up opens");
        let after = node.index.borrow().table(0, 48);
        assert_ne!(before, after, "CALIBRATION: the fold after the fetch changed the shard's table");
        let mut got = cu.note(&wants);
        got.sort();
        let mut want_roots: Vec<(usize, u64, Digest4)> = wants.iter().map(|(l, w)| (*l, *w, root(*l, *w))).collect();
        want_roots.sort();
        assert_eq!(got, want_roots, "⛔⛔ DB-405: a fold after the fetch gave the wallet a root the node never recorded");
    }

    /// ⭐ DB-223 Q2 §12d H — THE CATCH-UP, CLIENT AGAINST THE NODE'S OWN DOORS, AND ITS CONSTANT SHAPE.
    /// The node side holds a PIR-mode table at `HIGH_LEVEL` (past `WHOLE_MAX_ROOTS`) and a WHOLE-mode one above it. Two
    /// notes need different windows; the client recovers EXACTLY the roots the node recorded (PIR and whole alike). A
    /// catch-up whose notes need OTHER windows — or nothing — asks the node the IDENTICAL sequence of (door, level)
    /// pairs, so what a node sees never depends on which windows, or whether any, the wallet needs.
    /// CALIBRATION: a tampered answer recovers a different root, never the recorded one (the carrier's refold is what
    /// then refuses it).
    /// TWO-PARTY-REVIEWED: the SERVER is the node library's own `WindowIndex` + `high_answer` + `extend_high_hint` (the
    /// code the four routes run); the CLIENT is this wallet module; the pin asserts they AGREE on every root.
    #[test]
    fn q2_h_the_catch_up_recovers_the_nodes_roots_and_asks_every_level_the_same_way() {
        let mut index = WindowIndex::new();
        for w in 0..(WHOLE_MAX_ROOTS as u64 + 300) {
            assert!(index.record(HIGH_LEVEL, w, root(HIGH_LEVEL, w)), "a high window is recorded");
        }
        for w in 0..40u64 {
            assert!(index.record(HIGH_LEVEL + 1, w, root(HIGH_LEVEL + 1, w)));
        }
        let node = NodeSide { index, seed: window_index::pir_seed(&[7u8; 32]), asked: RefCell::new(Vec::new()) };
        let p = node.params().expect("params");
        assert!(p.levels.iter().any(|l| l.level == HIGH_LEVEL && l.pir), "PRECONDITION: one PIR-mode level");
        assert!(p.levels.iter().any(|l| l.level == HIGH_LEVEL + 1 && !l.pir && l.len > 0), "PRECONDITION: one WHOLE level");
        let ctr = RefCell::new(0u64);
        let fresh = || {
            *ctr.borrow_mut() += 1;
            *blake3::hash(&ctr.borrow().to_le_bytes()).as_bytes()
        };

        let run = |wants: [&[(usize, u64)]; 2]| {
            node.asked.borrow_mut().clear();
            let cu = CatchUp::new(&node).expect("the catch-up opens");
            let mut got: Vec<(usize, u64, Digest4)> = Vec::new();
            for w in wants {
                got.extend(cu.note(w, fresh).expect("the note's catch-up answers"));
            }
            got.sort();
            (got, node.asked.borrow().clone())
        };
        let (got, shape_a) = run([&[(HIGH_LEVEL, 4_321), (HIGH_LEVEL + 1, 17)], &[(HIGH_LEVEL, 9)]]);
        let mut want_roots = vec![
            (HIGH_LEVEL, 4_321u64, root(HIGH_LEVEL, 4_321)),
            (HIGH_LEVEL + 1, 17, root(HIGH_LEVEL + 1, 17)),
            (HIGH_LEVEL, 9, root(HIGH_LEVEL, 9)),
        ];
        want_roots.sort();
        assert_eq!(got, want_roots, "⛔ the wallet did not recover the roots the node recorded");
        let (_, shape_b) = run([&[(HIGH_LEVEL + 1, 3)], &[]]);
        assert_eq!(shape_b, shape_a, "⛔ what the node sees depends on which windows the wallet needs");
        assert_eq!(shape_a.iter().filter(|(d, _)| *d == "query").count(), 2, "one query per note per PIR level");

        // TAMPER: a flipped high bit in the answer moves the decoded byte by a whole Δ step.
        struct Tampered<'a>(&'a NodeSide);
        impl HighIndex for Tampered<'_> {
            fn params(&self) -> Result<HighParams, String> {
                self.0.params()
            }
            fn table(&self, level: usize) -> Result<Vec<u8>, String> {
                self.0.table(level)
            }
            fn hint(&self, level: usize) -> Result<Hinted, String> {
                self.0.hint(level)
            }
            fn answer(&self, level: usize, h: &Hinted, queries: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
                let mut a = self.0.answer(level, h, queries)?;
                // Every row's high byte: both roots of the column (either cell) decode wrong.
                for b in a[0].iter_mut().skip(3).step_by(4) {
                    *b ^= 0x80;
                }
                Ok(a)
            }
        }
        let tampered = Tampered(&node);
        let bad = CatchUp::new(&tampered).expect("opens").note(&[(HIGH_LEVEL, 4_321)], fresh).expect("answers");
        assert!(
            !bad.contains(&(HIGH_LEVEL, 4_321, root(HIGH_LEVEL, 4_321))),
            "CALIBRATION: a tampered answer must not recover the recorded root"
        );
    }
}
