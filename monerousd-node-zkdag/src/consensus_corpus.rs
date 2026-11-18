// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE FROZEN-CONSENSUS CORPUS — Bitcoin's implicit IBD regression check, made explicit.**
//!
//! Bitcoin's consensus is "frozen" by two things: rule changes are soft forks activated at a height, and
//! EVERY node replays the whole chain from genesis at IBD, so a change that would refuse (or re-value)
//! an old block cannot ship — the node forks off the network at that block within minutes of its first
//! sync. MonerousD is O(1) by construction: a node JUMPS to the tip by a certified bundle and never
//! replays history, so it lacks that implicit check — a consensus edit that silently changes what the
//! gates accept, or what a block folds to, could ship with every in-process pin green (the producer and
//! the verifier change together). This module is the explicit form: a RECORDED chain — real blocks a
//! real run produced through the money path (two free seats, a 2-of-2 peg-in mint, a 2-of-2 peg-out
//! burn) — stored as DATA beside the code and replayed on a fresh node from genesis by the CURRENT
//! consensus, every block required to be accepted and the final roots required to be byte-identical.
//! Ethereum's `consensus-spec-tests` are the same instrument; the O(1) node needs it MORE than Bitcoin
//! does, because nothing in production ever re-runs the past.
//!
//! What it is NOT: node state. The file is a test fixture bounded by `CORPUS_MAX_BYTES`; no node reads
//! it, no message carries it, nothing about it tracks height. Re-recording it (`MUSDM_CORPUS_RECORD=1`
//! on the recording pin) is the explicit hard-fork moment: a red replay means EITHER a defect in the
//! edit OR a deliberate consensus change that must be named, reviewed and re-recorded — never quietly.
//! Bitcoin gets that review for free from `getblock` on the old chain; we get it from this file.

use crate::block::Block;
use crate::node::Node;
use crate::relay::RelayOutcome;
use std::path::PathBuf;

/// The file's first bytes: a corpus recorded under one format is never read as another.
/// v2 (2026-10-26): the corpus also carries the DA records its blocks commit to. Since G1-DA a block commits to its
/// record (note payload) and a holder serves it on the by-id lane; a block-only replay folded 0 of 7 blocks.
/// v3 (2026-11-02, R4): every block is stored as (literal, zero-run) pairs ([`squeeze_zeros`]) — an armed fixture's ledger
/// doubles travel padded to the real proofs' weight (`note_transition::bound_weight`, runs of zero bytes), and the
/// re-recorded corpus measured 12,049,239 B raw against the 8 MiB bound; decode restores the byte-identical block.
/// Re-recorded 2026-11-03 (R4 lever 4 step C2), a NAMED consensus-format change with the file format unchanged: a ledger
/// block's note, tag and member ledgers are ONE joined proof in `NoteTransition::agg` (`tag_agg` and the member `agg`
/// empty), and the armed doubles' three seals weigh that one proof (`note_transition::bound_weight::LEDGER_JOINED`).
/// Re-recorded 2026-11-03 (arity 23), a NAMED consensus-format change with the file format unchanged: the tag ledger's rows tie directly to the
/// note ledger's published tags (`tag_ledger::note_tags_tie`); its pair-digest blocks and chain table are gone, the joined proof weighed 917,187 B
/// then. 2026-11-16 (V2, lane speed5): the joined proof is the note statement as the TREE LEDGER plus the member statement, no tag
/// statement — 369,545 B (`bound_weight::LEDGER_JOINED` holds the measured value).
pub const CORPUS_MAGIC: &[u8] = b"MUSDM-CONSENSUS-CORPUS-v3\n";

/// A zero run shorter than this stays literal (a run token costs 8 bytes; short runs are ordinary data).
const ZERO_RUN_MIN: usize = 64;

/// A block's bytes as `[literal_len u32][literal][zero_run u32]…` — exact, and only long zero runs shrink.
fn squeeze_zeros(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() / 4);
    let mut i = 0;
    while i < b.len() {
        let lit = i;
        while i < b.len() {
            if b[i] == 0 {
                let mut j = i;
                while j < b.len() && b[j] == 0 {
                    j += 1;
                }
                if j - i >= ZERO_RUN_MIN {
                    break;
                }
                i = j;
            } else {
                i += 1;
            }
        }
        let mut j = i;
        while j < b.len() && b[j] == 0 {
            j += 1;
        }
        out.extend_from_slice(&((i - lit) as u32).to_le_bytes());
        out.extend_from_slice(&b[lit..i]);
        out.extend_from_slice(&((j - i) as u32).to_le_bytes());
        i = j;
    }
    out
}

/// The inverse of [`squeeze_zeros`]; refuses a token past the input, or a block that expands past one bulk frame.
fn expand_zeros(s: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut c = Cur { b: s, at: 0 };
    while c.at < s.len() {
        let lit = c.u32()? as usize;
        out.extend_from_slice(c.take(lit)?);
        let run = c.u32()? as usize;
        if out.len() + run > crate::arti_transport::BULK_FRAME_MAX {
            return Err("a corpus block expands past one bulk frame".into());
        }
        out.resize(out.len() + run, 0);
    }
    Ok(out)
}
/// O1: the fixture's byte bound — a fixed test constant, never a function of chain state. A corpus that
/// grew past it would be a growth axis smuggled into the repository; the writer and the reader both
/// refuse it.
pub const CORPUS_MAX_BYTES: usize = 8 * 1024 * 1024;
/// O1: how many recorded blocks a corpus may carry (the money path takes five; sixty-four leaves room
/// for every class without letting the fixture become a chain).
pub const CORPUS_MAX_BLOCKS: usize = 64;
/// O1: how many named roots / classes a corpus freezes (the fourteen below; bounded so a decode of
/// hostile bytes cannot allocate past a constant).
pub const CORPUS_MAX_ROOTS: usize = 32;
/// O1: how many DA records a corpus may carry (at most one per recorded block).
pub const CORPUS_MAX_RECORDS: usize = CORPUS_MAX_BLOCKS;
/// O1: the longest root name / class name the format accepts.
pub const CORPUS_NAME_MAX: usize = 64;

/// What a recording run collects: every block a NON-PRODUCING party ingested, in its delivery order,
/// with the clock it ingested it at (the gates that read time replay under the same clock).
#[derive(Default)]
pub struct Recorder {
    /// O1-FOOTPRINT-REVIEWED: bounded by CORPUS_MAX_BLOCKS (asserted in `push`; a test-only recorder).
    pub blocks: Vec<(u64, Block)>,
}

impl Recorder {
    pub fn push(&mut self, ingest_ts: u64, block: Block) {
        assert!(self.blocks.len() < CORPUS_MAX_BLOCKS, "a corpus carries at most {CORPUS_MAX_BLOCKS} blocks");
        self.blocks.push((ingest_ts, block));
    }
}

/// The recorded chain as data: the blocks (postcard bytes — the wire encoding the relay lane itself
/// uses, so an encoding drift is a red replay too), the classes the run carried (so the replay can
/// refuse a corpus that proves nothing about a class it claims), and the roots the recording party
/// held at the end.
pub struct Corpus {
    /// O1-FOOTPRINT-REVIEWED: bounded by CORPUS_MAX_BLOCKS (`decode` refuses more; `encode` asserts).
    pub blocks: Vec<(u64, Vec<u8>)>,
    /// The DA records the replay's fold asks for, by record id (the record's canonical address), as the recording
    /// mesh's holders served them. Each still enters through the production door, judged against the replaying
    /// node's own root — a record that no longer matches its block is refused there, a red replay.
    /// O1-FOOTPRINT-REVIEWED: bounded by CORPUS_MAX_RECORDS (`decode` refuses more; `encode` asserts).
    /// §20.2: each record's bytes travel with its COVER KEY (the recording party's draw), exactly as the record lane carries
    /// them — a replay's fold assembles and binds the record under it.
    pub records: Vec<(u64, Vec<u8>, [u8; 32])>,
    /// O1-FOOTPRINT-REVIEWED: bounded by CORPUS_MAX_ROOTS (`decode` refuses more; `encode` asserts).
    pub classes: Vec<String>,
    /// O1-FOOTPRINT-REVIEWED: bounded by CORPUS_MAX_ROOTS (`decode` refuses more; `encode` asserts).
    pub roots: Vec<(String, Vec<u8>)>,
}

/// Where the corpus lives: beside the code, under source control, like `consensus_scenarios.txt`.
pub fn corpus_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("src");
    p.push("consensus_corpus.bin");
    p
}

/// The node the corpus was recorded against and is replayed on: the testnet genesis, records folding
/// at the tip (the money-path pins' shape). A corpus is only meaningful against the params it names.
pub fn corpus_node() -> Node {
    let mut p = crate::params::ChainParams::default();
    p.genesis_parity_commit = crate::params::network_genesis_prefix("testnet");
    p.net_prefix_len = p.genesis_parity_commit.len();
    p.record_fold_depth = 0;
    let mut g = crate::block::genesis_block();
    g.header = crate::block::genesis_header_for_network(&crate::params::network_genesis_prefix("testnet"));
    Node::with_params(g, p).expect("a testnet node builds")
}

/// Every consensus root a fresh replay must land on byte-for-byte. Public commitments only (the same
/// figures the DSYNC bundle certifies) — never a note, amount, key or owner.
pub fn roots_of(node: &Node) -> Vec<(String, Vec<u8>)> {
    let d4 = |d: &crate::spend_frontier::Digest4| crate::spend_frontier::digest_to_lane_bytes(d).to_vec();
    vec![
        ("state_root".to_string(), d4(&node.state_root())),
        ("nf_unspent_acc".to_string(), d4(&node.nf_unspent_acc())),
        ("membership_acc".to_string(), d4(&node.membership_acc())),
        ("spend_frontier_root".to_string(), d4(&node.spend_frontier_root())),
        ("root_history_root".to_string(), d4(&node.root_history_root())),
        ("account_root".to_string(), node.account_root().0.to_vec()),
        ("note_frontier_root".to_string(), node.note_frontier_root().0.to_vec()),
        ("nullifier_root".to_string(), node.nullifier_root().to_vec()),
        ("peg_reserve_commit".to_string(), d4(&node.peg().reserve_commit())),
        ("peg_minted_commit".to_string(), d4(&node.peg().minted_commit())),
        ("validators".to_string(), (node.validators().len() as u64).to_le_bytes().to_vec()),
        ("selected_tip".to_string(), node.selected_tip().map(|t| t.0.to_vec()).unwrap_or_default()),
    ]
}

fn put_name(out: &mut Vec<u8>, name: &str) {
    assert!(name.len() <= CORPUS_NAME_MAX, "a corpus name is at most {CORPUS_NAME_MAX} bytes");
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
}

pub fn encode(c: &Corpus) -> Vec<u8> {
    assert!(c.blocks.len() <= CORPUS_MAX_BLOCKS && c.records.len() <= CORPUS_MAX_RECORDS && c.roots.len() <= CORPUS_MAX_ROOTS && c.classes.len() <= CORPUS_MAX_ROOTS);
    let mut out = Vec::new();
    out.extend_from_slice(CORPUS_MAGIC);
    out.extend_from_slice(&(c.blocks.len() as u32).to_le_bytes());
    for (ts, bytes) in &c.blocks {
        let squeezed = squeeze_zeros(bytes);
        out.extend_from_slice(&ts.to_le_bytes());
        out.extend_from_slice(&(squeezed.len() as u32).to_le_bytes());
        out.extend_from_slice(&squeezed);
    }
    out.extend_from_slice(&(c.records.len() as u32).to_le_bytes());
    for (rid, bytes, key) in &c.records {
        out.extend_from_slice(&rid.to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
        out.extend_from_slice(key); // §20.2
    }
    out.extend_from_slice(&(c.classes.len() as u32).to_le_bytes());
    for name in &c.classes {
        put_name(&mut out, name);
    }
    out.extend_from_slice(&(c.roots.len() as u32).to_le_bytes());
    for (name, bytes) in &c.roots {
        put_name(&mut out, name);
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    assert!(out.len() <= CORPUS_MAX_BYTES, "the corpus is {} bytes, over CORPUS_MAX_BYTES", out.len());
    out
}

struct Cur<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.at + n > self.b.len() {
            return Err(format!("corpus truncated at byte {} (wanted {n})", self.at));
        }
        let s = &self.b[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn name(&mut self) -> Result<String, String> {
        let n = self.take(1)?[0] as usize;
        if n > CORPUS_NAME_MAX {
            return Err(format!("corpus name of {n} bytes over CORPUS_NAME_MAX"));
        }
        String::from_utf8(self.take(n)?.to_vec()).map_err(|e| e.to_string())
    }
}

pub fn decode(b: &[u8]) -> Result<Corpus, String> {
    if b.len() > CORPUS_MAX_BYTES {
        return Err(format!("corpus of {} bytes over CORPUS_MAX_BYTES", b.len()));
    }
    let mut c = Cur { b, at: 0 };
    if c.take(CORPUS_MAGIC.len())? != CORPUS_MAGIC {
        return Err("not a MUSDM consensus corpus (magic)".into());
    }
    let n = c.u32()? as usize;
    if n > CORPUS_MAX_BLOCKS {
        return Err(format!("corpus claims {n} blocks, over CORPUS_MAX_BLOCKS"));
    }
    let mut blocks = Vec::with_capacity(n);
    for _ in 0..n {
        let ts = c.u64()?;
        let len = c.u32()? as usize;
        blocks.push((ts, expand_zeros(c.take(len)?)?));
    }
    let n = c.u32()? as usize;
    if n > CORPUS_MAX_RECORDS {
        return Err(format!("corpus claims {n} records, over CORPUS_MAX_RECORDS"));
    }
    let mut records = Vec::with_capacity(n);
    for _ in 0..n {
        let rid = c.u64()?;
        let len = c.u32()? as usize;
        let bytes = c.take(len)?.to_vec();
        let key: [u8; 32] = c.take(32)?.try_into().map_err(|_| "a record's cover key is short".to_string())?;
        records.push((rid, bytes, key));
    }
    let n = c.u32()? as usize;
    if n > CORPUS_MAX_ROOTS {
        return Err(format!("corpus claims {n} classes, over CORPUS_MAX_ROOTS"));
    }
    let mut classes = Vec::with_capacity(n);
    for _ in 0..n {
        classes.push(c.name()?);
    }
    let n = c.u32()? as usize;
    if n > CORPUS_MAX_ROOTS {
        return Err(format!("corpus claims {n} roots, over CORPUS_MAX_ROOTS"));
    }
    let mut roots = Vec::with_capacity(n);
    for _ in 0..n {
        let name = c.name()?;
        let len = c.u32()? as usize;
        roots.push((name, c.take(len)?.to_vec()));
    }
    if c.at != b.len() {
        return Err(format!("{} trailing bytes after the corpus", b.len() - c.at));
    }
    Ok(Corpus { blocks, records, classes, roots })
}

/// THE REPLAY: a fresh node from genesis ingests every recorded block under the recorded clock through
/// the CURRENT consensus, and settles as a lone node's runtime does — the records its fold asks for come from the
/// corpus through the production door. Any block the current gates refuse ends the replay with that verdict — the
/// exact signal Bitcoin's IBD gives a node whose rules drifted from the chain's.
#[cfg(test)]
pub fn replay(corpus: &Corpus) -> Result<Vec<(String, Vec<u8>)>, String> {
    let held = |rid: u64| corpus.records.iter().find(|(r, _, _)| *r == rid).map(|(_, b, k)| (b.clone(), Some(*k)));
    replay_with(&corpus.blocks, &held).map(|(roots, _)| roots)
}

/// The replay over any record holder; returns the roots and every record the fold took, in the order it took them
/// (the recorder freezes exactly that set).
#[cfg(test)]
fn replay_with(
    blocks: &[(u64, Vec<u8>)],
    holder: &dyn Fn(u64) -> Option<(Vec<u8>, Option<crate::cover::CoverKey>)>,
) -> Result<(Vec<(String, Vec<u8>)>, Vec<(u64, Vec<u8>, [u8; 32])>), String> {
    let taken = std::cell::RefCell::new(Vec::<(u64, Vec<u8>, [u8; 32])>::new());
    let tap = |rid: u64| {
        let got = holder(rid);
        if let Some((b, k)) = &got {
            if !taken.borrow().iter().any(|(r, _, _)| *r == rid) {
                // §20.2: a record the fold takes is frozen WITH its key; a holder that served none froze nothing usable
                taken.borrow_mut().push((rid, b.clone(), k.unwrap_or_else(|| crate::cover::idle_cover_key(rid))));
            }
        }
        got
    };
    let mut node = corpus_node();
    for (i, (ts, bytes)) in blocks.iter().enumerate() {
        // §22: a recorded block is its gossip envelope (wire form ‖ cover key) — what a peer receives; `gossip_decode`
        // refuses any other trailing bytes, so "decodes exactly" still holds for the wire form inside it.
        let block: Block = crate::block::gossip_decode(bytes)
            .ok_or_else(|| format!("recorded block {i} no longer decodes EXACTLY under the current wire encoding (one object, one encoding)"))?;
        match node.ingest_block(block, *ts) {
            RelayOutcome::Added(_) => {}
            other => return Err(format!("recorded block {i} is refused by the current consensus: {other:?}")),
        }
        settle_lone(&mut node, &tap, blocks.len());
    }
    let roots = roots_of(&node);
    Ok((roots, taken.into_inner()))
}

/// A lone full node's runtime, in one bounded loop: take the records its fold wants from `holder` (the by-id lane,
/// production door), fold, prove its own band steps (DB-353 §13.6: a fold that admits a nullifier waits for that
/// step's band transition) — until nothing lands, folds or proves. MEASURED 2026-10-26: a replay that only grafted
/// folded 0 of 7 blocks ("the block's record … is not held here"), 8 of 12 roots diverged. Each pass that continues
/// lands, folds or proves at least one thing for a block of this fixture, so `3 · blocks + 2` passes bound it.
#[cfg(test)]
pub fn settle_lone(node: &mut Node, holder: &dyn Fn(u64) -> Option<(Vec<u8>, Option<crate::cover::CoverKey>)>, blocks: usize) {
    for _ in 0..3 * blocks + 2 {
        let landed = node.deliver_records_from_for_test(holder);
        let folded = node.fold_canonical_records();
        let steps = node.band_catch_up_for_test();
        if landed == 0 && folded == 0 && steps.is_empty() {
            break;
        }
    }
}

/// Called at the end of a recording pin. With `MUSDM_CORPUS_RECORD=1` set it writes the corpus the run
/// produced (the explicit, reviewed act of re-freezing consensus); otherwise it does nothing, so the
/// pin's own verdict is never a function of the environment.
#[cfg(test)]
pub fn maybe_record(rec: &Recorder, party: &Node, classes: &[&str]) {
    if std::env::var("MUSDM_CORPUS_RECORD").is_err() {
        return;
    }
    let blocks: Vec<(u64, Vec<u8>)> =
        rec.blocks.iter().map(|(ts, b)| (*ts, crate::block::gossip_encode(b))).collect(); // §22: the envelope, as a peer receives it
    // The records are the ones a fresh replay's fold asks for, served by the recording party — a dry replay at record
    // time, so a corpus that does not reproduce the party's roots is never written.
    let (dry, records) = replay_with(&blocks, &|rid| party.ledger_record_for_rid(rid).map(|r| (r.notes.clone(), r.key())))
        .unwrap_or_else(|e| panic!("⛔ the recorded chain does not replay on the commit that recorded it: {e}"));
    let want = roots_of(party);
    let differs: Vec<&str> =
        dry.iter().zip(want.iter()).filter(|(d, w)| d.1 != w.1).map(|(d, _)| d.0.as_str()).collect();
    assert!(differs.is_empty(), "⛔ a fresh replay of the recorded chain does not reach the party's roots: {differs:?}");
    let corpus = Corpus {
        blocks,
        records,
        classes: classes.iter().map(|s| s.to_string()).collect(),
        roots: roots_of(party),
    };
    let bytes = encode(&corpus);
    let path = corpus_path();
    std::fs::write(&path, &bytes).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    eprintln!(
        "[corpus] RECORDED {} block(s), {} record(s), {} byte(s), classes {:?} -> {}",
        corpus.blocks.len(),
        corpus.records.len(),
        bytes.len(),
        corpus.classes,
        path.display()
    );
}

fn load() -> Corpus {
    let path = corpus_path();
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "⛔ NO FROZEN-CONSENSUS CORPUS at {} ({e}). Record it: MUSDM_CORPUS_RECORD=1 cargo test --release \
             node::pins::a_two_of_two_custody_quorum_gathers_peg_out_attestations_and_a_third_node_applies_the_burn_from_the_block \
             — a missing corpus is a missing gate, never a pass.",
            path.display()
        )
    });
    decode(&bytes).unwrap_or_else(|e| panic!("⛔ the frozen corpus at {} does not decode: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE FROZEN-CONSENSUS PIN. Red means one of two things and both need a name: a defect that changed
    /// what the gates accept or what a block folds to, or a deliberate consensus change — which is then
    /// re-recorded ON PURPOSE (`MUSDM_CORPUS_RECORD=1`), reviewed as the hard fork it is.
    #[test]
    fn the_frozen_corpus_replays_byte_identical_under_the_current_consensus() {
        let corpus = load();
        let roots = replay(&corpus).unwrap_or_else(|e| panic!("⛔ FROZEN CONSENSUS BROKEN: {e}"));
        assert_eq!(roots.len(), corpus.roots.len(), "the root list changed shape — name the new root and re-record");
        // Every diverging root is named in one verdict: the first mismatch alone hides whether one half of a
        // composite root (state_root = pair(notes, nullifiers)) moved or both did.
        let mut differs = Vec::new();
        for ((name, got), (rec_name, rec)) in roots.iter().zip(corpus.roots.iter()) {
            assert_eq!(name, rec_name, "the root list changed order/name");
            if got != rec {
                differs.push(name.as_str());
            }
        }
        assert!(
            differs.is_empty(),
            "⛔ FROZEN CONSENSUS BROKEN: {differs:?} no longer fold to what the recorded chain folded to \
             (every recorded block was still ACCEPTED — the gates let a different state through)"
        );
        eprintln!(
            "[corpus] {} recorded block(s) replayed under the current consensus, {} root(s) byte-identical",
            corpus.blocks.len(),
            roots.len()
        );
    }

    /// Calibration (refutation before green): the replay RUNS the gates — a recorded block whose work
    /// was flipped is refused, so a green replay is a verdict and not a walk.
    #[test]
    fn the_corpus_replay_refuses_a_block_whose_work_was_flipped() {
        let mut corpus = load();
        let last = corpus.blocks.len() - 1;
        let mut block: Block = crate::block::gossip_decode(&corpus.blocks[last].1).expect("decodes");
        assert!(!block.pow_proof.is_empty(), "the recorded block carries its work");
        block.pow_proof[0] ^= 1;
        corpus.blocks[last].1 = crate::block::gossip_encode(&block);
        let verdict = replay(&corpus);
        assert!(verdict.is_err(), "⛔ a block with flipped work replayed as accepted: {:?}", verdict.map(|r| r.len()));
    }

}
