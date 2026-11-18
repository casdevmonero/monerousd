//! ⭐⭐⭐ THE `Node` FIELD CENSUS — the digest both censuses compare. The field list is DERIVED from `pub struct Node` by
//! `node_census_derive::NodeFieldCensus` (DB-402 R2: no hand-written or script-generated list exists to go stale).
//!
//! user 2026-10-06 (the restart census): a restart must give back the state the process held. DB-402 R1 (the replicated-state
//! census): two nodes holding the same chain must hold the same value in every field that is not node-local. Every field of
//! `Node` is printed (`{:?}`), canonicalised (entries inside braces combined order-insensitively, so a rebuilt HashMap's
//! iteration order never reads as a change) and compared. A field whose type cannot be printed digests to `None` and must be
//! stood in for (`restart_census_stand_ins::STOOD_IN`) or declared with a reason (`VOLATILE` / `NODE_LOCAL`).
use super::Node;

/// DB-402 R2 — AUTOREF SPECIALIZATION: `(&Probe(&self.f)).census_digest()` resolves to [`DigestViaDebug`] when the field's
/// type is `Debug` (a by-value match on `&Probe`) and to [`DigestUnprintable`] otherwise (one autoref later), so the derived
/// census compiles for every field type and an unprintable one reads `None` — never a build break, never a silent skip
/// (the completeness pin refuses a `None` nothing stands in for).
pub(crate) struct Probe<'a, T: ?Sized>(pub &'a T);

pub(crate) trait DigestViaDebug {
    fn census_digest(&self) -> Option<(u64, usize)>;
}

impl<T: std::fmt::Debug + ?Sized> DigestViaDebug for Probe<'_, T> {
    fn census_digest(&self) -> Option<(u64, usize)> {
        Some(canonical_debug_of(self.0))
    }
}

/// A field whose type is not `Debug`: `None`, which the completeness pin refuses unless a stand-in or a reason names it.
pub(crate) trait DigestUnprintable {
    fn census_digest(&self) -> Option<(u64, usize)>;
}

impl<T: ?Sized> DigestUnprintable for &Probe<'_, T> {
    fn census_digest(&self) -> Option<(u64, usize)> {
        None
    }
}

/// DB-402 R1 triage — the same autoref specialization, streaming the field's `{:?}` into any sink (the first-difference
/// instrument, [`first_difference`]): `false` when the type cannot be printed.
pub(crate) trait RenderViaDebug {
    fn census_render(&self, out: &mut dyn std::fmt::Write) -> bool;
}

impl<T: std::fmt::Debug + ?Sized> RenderViaDebug for Probe<'_, T> {
    fn census_render(&self, out: &mut dyn std::fmt::Write) -> bool {
        out.write_fmt(format_args!("{:?}", self.0)).is_ok()
    }
}

pub(crate) trait RenderUnprintable {
    fn census_render(&self, out: &mut dyn std::fmt::Write) -> bool;
}

impl<T: ?Sized> RenderUnprintable for &Probe<'_, T> {
    fn census_render(&self, _out: &mut dyn std::fmt::Write) -> bool {
        false
    }
}

/// The first-difference instrument's chunk: a rendering is compared in chunks of this many bytes, so finding where two
/// renderings part never builds either text (a field can render to hundreds of MB) — it holds one hash per chunk and two
/// chunks of text.
const DIFF_CHUNK: usize = 4096;

/// How many of the last `name:` / `key:` tokens the instrument keeps while streaming (a constant, never a reach bound:
/// it is how much of the path to the difference is printed).
const DIFF_NAMES: usize = 6;

/// Streams a rendering, hashing it chunk by chunk; captures the first chunk that differs from `against` (pass 2) or chunk
/// `want` (pass 3), with the chunk before it. While streaming it keeps the last [`DIFF_NAMES`] `token:` labels (field
/// names and map keys), snapshotted where the captured context begins, so a difference deep inside one long map entry
/// still names the entry's key.
struct ChunkSink {
    hashes: Vec<u64>,
    cur: u64,
    cur_len: usize,
    total: usize,
    against: Option<Vec<u64>>,
    want: Option<usize>,
    prev: Vec<u8>,
    buf: Vec<u8>,
    hit: Option<(usize, Vec<u8>, Vec<u8>)>,
    tok: Vec<u8>,
    names: std::collections::VecDeque<String>,
    names_at_prev: Vec<String>,
    names_at_cur: Vec<String>,
}

impl ChunkSink {
    fn new(against: Option<Vec<u64>>, want: Option<usize>) -> ChunkSink {
        ChunkSink {
            hashes: Vec::new(),
            cur: SEED,
            cur_len: 0,
            total: 0,
            against,
            want,
            prev: Vec::new(),
            buf: Vec::new(),
            hit: None,
            tok: Vec::new(),
            names: std::collections::VecDeque::new(),
            names_at_prev: Vec::new(),
            names_at_cur: Vec::new(),
        }
    }
    fn close_chunk(&mut self) {
        let k = self.hashes.len();
        self.hashes.push(self.cur);
        let differs = self.against.as_ref().is_some_and(|a| a.get(k) != Some(&self.cur));
        if self.hit.is_none() && (differs || self.want == Some(k)) {
            self.hit = Some((k, std::mem::take(&mut self.prev), std::mem::take(&mut self.buf)));
        }
        if self.hit.is_none() {
            // the labels in force where the captured context (the chunk before the hit) begins
            self.names_at_prev = std::mem::replace(&mut self.names_at_cur, self.names.iter().cloned().collect());
        }
        self.prev = std::mem::take(&mut self.buf);
        self.cur = SEED;
        self.cur_len = 0;
    }
    fn track_label(&mut self, b: u8) {
        if b.is_ascii_alphanumeric() || b == b'_' {
            if self.tok.len() < 64 {
                self.tok.push(b);
            }
            return;
        }
        if b == b':' && !self.tok.is_empty() {
            if self.names.len() == DIFF_NAMES {
                self.names.pop_front();
            }
            self.names.push_back(String::from_utf8_lossy(&self.tok).into_owned());
        }
        self.tok.clear();
    }
    fn finish(mut self) -> ChunkSink {
        if self.cur_len > 0 || self.hashes.is_empty() {
            self.close_chunk();
        }
        // a rendering that is a strict prefix of the other: the first chunk it lacks is where they part
        if self.hit.is_none() && self.against.as_ref().is_some_and(|a| a.len() > self.hashes.len()) {
            self.hit = Some((self.hashes.len(), std::mem::take(&mut self.prev), Vec::new()));
        }
        self
    }
}

impl std::fmt::Write for ChunkSink {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        for &b in s.as_bytes() {
            self.cur = mix_byte(self.cur, b);
            self.cur_len += 1;
            self.total += 1;
            if self.hit.is_none() {
                self.buf.push(b);
                self.track_label(b);
            }
            if self.cur_len == DIFF_CHUNK {
                self.close_chunk();
            }
        }
        Ok(())
    }
}

/// ⭐ DB-402 R1 TRIAGE — WHERE two renderings of one field part, so a DIFFERS row names its cause instead of a digest.
/// `render(side, out)` streams side a (`false`) or b (`true`); it is called three times (hash a chunk by chunk, find the
/// first chunk of b that differs, capture that chunk of a), so one hash per chunk and two chunks of text are all it holds.
/// Returns `Err` naming why no context was captured (identical renderings, or a capture pass that saw no chunk), else
/// `(byte offset, len a, len b, context a, context b)`: up to `ctx` bytes either side of the first differing byte, led by
/// the last field names (`name:`) before it. Raw text: a HashMap may print in another order on each side, which the
/// canonical digest forgives — read the context with that in mind.
pub(crate) fn first_difference(
    render: &dyn Fn(bool, &mut dyn std::fmt::Write) -> bool,
    ctx: usize,
) -> Result<(usize, usize, usize, String, String), String> {
    let mut a = ChunkSink::new(None, None);
    render(false, &mut a);
    let a = a.finish();
    let mut b = ChunkSink::new(Some(a.hashes.clone()), None);
    render(true, &mut b);
    let b = b.finish();
    let Some((k, b_prev, b_chunk)) = b.hit else {
        return Err(format!("the raw renderings are identical ({} bytes) — the canonical digests cannot differ", a.total));
    };
    let b_names = b.names_at_prev;
    let mut a2 = ChunkSink::new(None, Some(k));
    render(false, &mut a2);
    let a2 = a2.finish();
    let Some((_, a_prev, a_chunk)) = a2.hit else {
        return Err(format!("side a rendered {} bytes on its capture pass, fewer than chunk {k} needs (a changed between passes?)", a2.total));
    };
    let a_names = a2.names_at_prev;
    let (sa, sb) = ([a_prev.as_slice(), a_chunk.as_slice()].concat(), [b_prev.as_slice(), b_chunk.as_slice()].concat());
    let base = if k > 0 { (k - 1) * DIFF_CHUNK } else { 0 };
    let shorter = sa.len().min(sb.len());
    let p = match sa.iter().zip(sb.iter()).position(|(x, y)| x != y) {
        Some(p) => p,
        None => shorter, // one side ends where the other goes on
    };
    // the labels in force at the difference: those streamed before the captured context, then those inside it
    let cut = |s: &[u8], streamed: &[String]| -> String {
        let lo = p.saturating_sub(ctx).min(s.len());
        let hi = (p + ctx).min(s.len());
        let mut probe = ChunkSink::new(None, None);
        probe.names = streamed.iter().cloned().collect();
        for &b in &s[..p.min(s.len())] {
            probe.track_label(b);
        }
        let labels: Vec<String> = probe.names.into_iter().collect();
        format!("[after {}] …{}…", labels.join(" "), String::from_utf8_lossy(&s[lo..hi]))
    };
    Ok((base + p, a.total, b.total, cut(&sa, &a_names), cut(&sb, &b_names)))
}

/// ⭐ DB-402 R1 TRIAGE (lane a 2026-10-22) — WHICH ITEMS of a map-shaped field one node holds and the other does not.
/// `first_difference` names the first byte where two renderings part, which for a map prints one item of each side —
/// `note_target_addr` read "7970 vs 8305 B, first difference at byte 3" for a run and said nothing about which keys
/// were extra. This streams each side's rendering, splits the OUTERMOST `{…}` into its items (commas at that depth,
/// strings respected) and returns, as text cut to `keep` bytes each, up to `max` items only side a holds, up to `max`
/// only side b holds, and the two item counts. Memory: one hash and at most `keep` bytes per item on each side (a
/// record-bytes field renders hundreds of MB, so the text is never kept whole). G1g-v (lane a 2026-10-23): the OUTERMOST
/// `[…]` splits the same way (a ring, a recent view: `relay`, `completed_windows` read "renders no map" for 4 restarts),
/// and a render with neither is ONE item, its whole text, so a changed scalar (`band_steps_applied`, `anchor_block_full`)
/// names both values. `Err` only when a side renders nothing.
pub(crate) fn set_difference(
    render: &dyn Fn(bool, &mut dyn std::fmt::Write) -> bool,
    keep: usize,
    max: usize,
) -> Result<(Vec<String>, Vec<String>, usize, usize), String> {
    const TAIL: usize = 48;
    struct ItemSink {
        keep: usize,
        depth: usize,
        container: Option<usize>,
        in_str: bool,
        esc: bool,
        cur: u64,
        cur_text: Vec<u8>,
        cur_tail: std::collections::VecDeque<u8>,
        cur_len: usize,
        items: Vec<(u64, String)>,
    }
    impl ItemSink {
        fn close_item(&mut self) {
            if self.cur_len > 0 {
                // a cut item keeps its head and its TAIL (a record row ends in its letter column and provenance bool)
                let mut text = String::from_utf8_lossy(&self.cur_text).into_owned();
                if self.cur_len > self.keep + TAIL {
                    text.push('…');
                    text.push_str(&String::from_utf8_lossy(self.cur_tail.make_contiguous()));
                }
                self.items.push((self.cur, text));
            }
            self.cur = SEED;
            self.cur_text.clear();
            self.cur_tail.clear();
            self.cur_len = 0;
        }
        fn feed(&mut self, b: u8) {
            if self.container != Some(usize::MAX) {
                // before the container opens the bytes are a scalar render's text (one item if no container ever opens)
                self.cur = mix_byte(self.cur, b);
                self.cur_len += 1;
                if self.cur_text.len() < self.keep {
                    self.cur_text.push(b);
                } else {
                    if self.cur_tail.len() == TAIL {
                        self.cur_tail.pop_front();
                    }
                    self.cur_tail.push_back(b);
                }
            }
        }
    }
    impl std::fmt::Write for ItemSink {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            for &b in s.as_bytes() {
                if self.in_str {
                    self.feed(b);
                    if self.esc {
                        self.esc = false;
                    } else if b == b'\\' {
                        self.esc = true;
                    } else if b == b'"' {
                        self.in_str = false;
                    }
                    continue;
                }
                match b {
                    b'"' => {
                        self.in_str = true;
                        self.feed(b);
                    }
                    b'{' | b'[' | b'(' => {
                        if self.container.is_none() && (b == b'{' || b == b'[') {
                            self.container = Some(self.depth);
                            // the prefix before the container (`Some(`, `(7, `) is not an item
                            self.cur = SEED;
                            self.cur_text.clear();
                            self.cur_tail.clear();
                            self.cur_len = 0;
                        } else {
                            self.feed(b);
                        }
                        self.depth += 1;
                    }
                    b'}' | b']' | b')' => {
                        self.depth = self.depth.saturating_sub(1);
                        if self.container == Some(self.depth) {
                            self.close_item();
                            self.container = Some(usize::MAX); // the outermost map is closed: nothing after it is an item
                        } else {
                            self.feed(b);
                        }
                    }
                    b',' if self.container.is_some_and(|c| c + 1 == self.depth) => self.close_item(),
                    b' ' | b'\n' | b'\t' => {} // whitespace outside strings is not content (as the canonical digest reads it)
                    _ => self.feed(b),
                }
            }
            Ok(())
        }
    }
    let side = |which: bool| -> Result<Vec<(u64, String)>, String> {
        let mut s = ItemSink {
            keep,
            depth: 0,
            container: None,
            in_str: false,
            esc: false,
            cur: SEED,
            cur_text: Vec::new(),
            cur_tail: std::collections::VecDeque::with_capacity(TAIL),
            cur_len: 0,
            items: Vec::new(),
        };
        render(which, &mut s);
        if s.container.is_none() && s.cur_len == 0 {
            return Err(format!("side {} renders nothing", if which { "b" } else { "a" }));
        }
        s.close_item(); // G1g-v: a scalar render (no map, no list) is ONE item — its whole text — so both sides are named
        Ok(s.items)
    };
    let (a, b) = (side(false)?, side(true)?);
    let ha: std::collections::HashSet<u64> = a.iter().map(|(h, _)| *h).collect();
    let hb: std::collections::HashSet<u64> = b.iter().map(|(h, _)| *h).collect();
    let only_a: Vec<String> = a.iter().filter(|(h, _)| !hb.contains(h)).take(max).map(|(_, t)| t.clone()).collect();
    let only_b: Vec<String> = b.iter().filter(|(h, _)| !ha.contains(h)).take(max).map(|(_, t)| t.clone()).collect();
    Ok((only_a, only_b, a.len(), b.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The set-difference printer is ARMED: an item held on one side only is named, a shared item is not, a list splits
    /// into its items, and a scalar render is one item on each side (both values named).
    #[test]
    fn the_set_difference_names_the_items_one_side_lacks() {
        let a: std::collections::BTreeMap<u64, &str> = [(1, "x"), (2, "y, with a comma"), (3, "z")].into_iter().collect();
        let b: std::collections::BTreeMap<u64, &str> = [(1, "x"), (3, "z"), (4, "w")].into_iter().collect();
        let render = |side: bool, out: &mut dyn std::fmt::Write| {
            if side { write!(out, "{:?}", b).is_ok() } else { write!(out, "{:?}", a).is_ok() }
        };
        let (oa, ob, la, lb) = set_difference(&render, 64, 8).expect("two maps");
        assert_eq!((la, lb), (3, 3));
        assert_eq!(oa, vec!["2:\"y, with a comma\"".to_string()], "the item only a holds, commas inside its string kept");
        assert_eq!(ob, vec!["4:\"w\"".to_string()], "the item only b holds");
        let wrapped = |side: bool, out: &mut dyn std::fmt::Write| {
            if side { write!(out, "Some({:?})", b).is_ok() } else { write!(out, "(7, {:?})", a).is_ok() }
        };
        let (oa, ob, _, _) = set_difference(&wrapped, 64, 8).expect("a wrapped map still splits at its outermost braces");
        assert_eq!((oa.len(), ob.len()), (1, 1));
        let list = |_: bool, out: &mut dyn std::fmt::Write| {
            write!(out, "{:?}", vec![1, 2]).is_ok()
        };
        let (oa, ob, la, lb) = set_difference(&list, 64, 8).expect("a list splits into its items");
        assert_eq!((oa, ob, la, lb), (vec![], vec![], 2, 2), "the same list on both sides: nothing named");
        let ring = |side: bool, out: &mut dyn std::fmt::Write| {
            if side { write!(out, "(9, {:?})", vec![(2u64, "b"), (3, "c")]).is_ok() } else { write!(out, "(9, {:?})", vec![(1u64, "a"), (2, "b")]).is_ok() }
        };
        let (oa, ob, la, lb) = set_difference(&ring, 64, 8).expect("a wrapped list splits at its outermost brackets");
        assert_eq!((la, lb), (2, 2));
        assert_eq!(oa, vec!["(1,\"a\")".to_string()], "the entry only a holds");
        assert_eq!(ob, vec!["(3,\"c\")".to_string()], "the entry only b holds");
        let scalar = |side: bool, out: &mut dyn std::fmt::Write| {
            write!(out, "Some((\"id{}\", \"digest\"))", if side { 2 } else { 1 }).is_ok()
        };
        let (oa, ob, la, lb) = set_difference(&scalar, 64, 8).expect("a scalar render is one item");
        assert_eq!((la, lb), (1, 1));
        assert_eq!(oa, vec!["Some((\"id1\",\"digest\"))".to_string()], "side a's whole value is named");
        assert_eq!(ob, vec!["Some((\"id2\",\"digest\"))".to_string()], "side b's whole value is named");
        let same = |_: bool, out: &mut dyn std::fmt::Write| out.write_str("7").is_ok();
        let (oa, ob, _, _) = set_difference(&same, 64, 8).expect("one scalar");
        assert!(oa.is_empty() && ob.is_empty(), "the same scalar on both sides: nothing named");
        let nothing = |_: bool, _: &mut dyn std::fmt::Write| true;
        assert!(set_difference(&nothing, 64, 8).is_err(), "a side that renders nothing is refused");
    }
}

/// A STREAMING canonical digest of a value's `{:?}` rendering — the text is never built (a field holding record bytes
/// renders to hundreds of MB; MEASURED 2026-10-06: the string-building first version tripped the 6 GB runtime cap).
/// At every `{…}` level the items are combined ORDER-INSENSITIVELY (a wrapping sum of their hashes: maps and sets print
/// in hash order, so a rebuilt HashMap never reads as a change); `[…]` and `(…)` hash their content in order; whitespace
/// outside strings is ignored. Returns the digest and the rendering's length in bytes.
pub(crate) fn canonical_debug_of<T: std::fmt::Debug + ?Sized>(v: &T) -> (u64, usize) {
    use std::fmt::Write;
    let mut sink = CanonSink::new();
    let _ = write!(sink, "{:?}", v);
    sink.finish()
}

/// [`canonical_debug_of`] over text already rendered (the stand-ins' small summaries).
pub(crate) fn canonical_debug(s: &str) -> (u64, usize) {
    use std::fmt::Write;
    let mut sink = CanonSink::new();
    let _ = sink.write_str(s);
    sink.finish()
}

const FNV: u64 = 0x0100_0000_01b3;
const SEED: u64 = 0xcbf2_9ce4_8422_2325;

fn mix_byte(h: u64, b: u8) -> u64 {
    (h ^ u64::from(b)).wrapping_mul(FNV)
}

fn mix_u64(mut h: u64, x: u64) -> u64 {
    for b in x.to_le_bytes() {
        h = mix_byte(h, b);
    }
    h
}

struct Frame {
    brace: bool,
    set_acc: u64,
    item: u64,
    item_len: usize,
}

impl Frame {
    fn new(brace: bool) -> Frame {
        Frame { brace, set_acc: 0, item: SEED, item_len: 0 }
    }
    fn close_item(&mut self) {
        if self.item_len > 0 {
            self.set_acc = self.set_acc.wrapping_add(mix_u64(SEED, self.item));
        }
        self.item = SEED;
        self.item_len = 0;
    }
}

struct CanonSink {
    stack: Vec<Frame>,
    in_str: bool,
    esc: bool,
    len: usize,
    /// the order-only probe ([`multiset_digest`]): `[…]` and `(…)` are combined order-insensitively too
    all_sets: bool,
}

/// ⭐ DB-402 R1 triage — the ORDER-ONLY probe: a digest of a rendering in which EVERY level, lists and tuples included,
/// combines its items order-insensitively. Two renderings the canonical digest calls different but this calls equal hold
/// the same items in a different ORDER — a node's arrival order leaking into a field that should be a function of the
/// chain, a different defect (and a different fix) from different content.
pub(crate) fn multiset_digest(render: &dyn Fn(&mut dyn std::fmt::Write) -> bool) -> u64 {
    let mut sink = CanonSink::new();
    sink.all_sets = true;
    render(&mut sink);
    sink.finish().0
}

impl CanonSink {
    fn new() -> CanonSink {
        CanonSink { stack: vec![Frame::new(false)], in_str: false, esc: false, len: 0, all_sets: false }
    }
    fn feed(&mut self, b: u8) {
        if let Some(top) = self.stack.last_mut() {
            top.item = mix_byte(top.item, b);
            top.item_len += 1;
        }
    }
    fn finish(mut self) -> (u64, usize) {
        while self.stack.len() > 1 {
            self.close_frame(b')');
        }
        let top = self.stack.pop().unwrap_or_else(|| Frame::new(false));
        (top.item, self.len)
    }
    fn close_frame(&mut self, close: u8) {
        let Some(mut f) = self.stack.pop() else { return };
        let value = if f.brace {
            f.close_item();
            mix_u64(mix_byte(SEED, b'{'), f.set_acc)
        } else {
            mix_u64(mix_byte(SEED, b'['), f.item)
        };
        if self.stack.is_empty() {
            self.stack.push(Frame::new(false));
        }
        if let Some(top) = self.stack.last_mut() {
            top.item = mix_byte(mix_u64(top.item, value), close);
            top.item_len += 1;
        }
    }
}

impl std::fmt::Write for CanonSink {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.len += s.len();
        for &b in s.as_bytes() {
            if self.in_str {
                self.feed(b);
                if self.esc {
                    self.esc = false;
                } else if b == b'\\' {
                    self.esc = true;
                } else if b == b'"' {
                    self.in_str = false;
                }
                continue;
            }
            match b {
                b'"' => {
                    self.in_str = true;
                    self.feed(b);
                }
                b'{' => self.stack.push(Frame::new(true)),
                b'[' | b'(' => self.stack.push(Frame::new(self.all_sets)),
                b'}' | b']' | b')' => self.close_frame(b),
                b',' if self.stack.last().is_some_and(|f| f.brace) => {
                    if let Some(top) = self.stack.last_mut() {
                        top.close_item();
                    }
                }
                b' ' | b'\n' | b'\t' => {}
                _ => self.feed(b),
            }
        }
        Ok(())
    }
}

impl Node {
    /// Every `Node` field, in declaration order: its canonical digest, or `None` when its type cannot be printed or a
    /// stand-in replaces it (the stand-in's own digest is what the censuses compare for those).
    pub(crate) fn restart_census_digest(&self) -> Vec<(&'static str, Option<(u64, usize)>)> {
        self.node_field_census(&super::restart_census_stand_ins::STOOD_IN)
    }
}
