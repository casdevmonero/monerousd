// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §22 6 — THE BUNDLED BITCOIN WATCHER'S CORE: BIP 157/158 compact block filters, checked by the node itself
//! (docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §22 6; user 2026-10-30: a validator needs nothing installed).
//!
//! Today's watcher asks an explorer's onion service for each reserve address's balance: the explorer is trusted for the
//! answer and LEARNS which addresses the bridge watches. A compact-filter client (the Neutrino shape, BIP 157/158) asks
//! nothing about any address: it downloads every block's filter, tests its own scripts locally, and fetches only the
//! blocks that match — and it checks the header chain's proof of work and difficulty itself, so a peer cannot invent a
//! deposit. This module is that client's pure core:
//! - the BIP 158 basic filter: SipHash-2-4 keyed by the block hash, Golomb-Rice coding with P = 19, M = 784931;
//! - the BIP 157 filter-header chain: `dSHA256(dSHA256(filter) ‖ previous header)`;
//! - Bitcoin's proof of work: a header's hash at or under the target its `nBits` declares, and the 2016-block retarget
//!   (`CalculateNextWorkRequired`, Bitcoin Core `pow.cpp`, borrowed line for line);
//! - the agreement rule the spec names: a filter header counts only when ≥ [`MIN_FILTER_PEERS`] distinct peers report it
//!   and none reports another — a disagreement is never settled by majority (the watcher asks other peers).
//!
//! Every function is calibrated against Bitcoin Core's own test data (`blockfilters.json`, `pow_tests.cpp`).
//!
//! CLASSICAL-BRIDGE-ENDPOINT: this is a FOREIGN chain's format, read-only — SHA-256 and SipHash are what Bitcoin's
//! headers and filters are made of; no key, no signature, nothing in MonerousD's own consensus uses them.
//! DIGITAL-CASH-PRIVACY-REVIEWED: filters are fetched for every block, so a peer learns nothing about which scripts match.

use sha2::{Digest, Sha256};

/// BIP 158 basic filter: Golomb-Rice parameter.
pub const P: u32 = 19;
/// BIP 158 basic filter: the false-positive inverse rate.
pub const M: u64 = 784_931;
/// Distinct peers that must report one filter header before it counts (§22 6).
pub const MIN_FILTER_PEERS: usize = 3;
/// Bitcoin's retarget timespan: two weeks.
pub const TARGET_TIMESPAN: i64 = 14 * 24 * 60 * 60;
/// Bitcoin's proof-of-work limit (mainnet and testnet3) in compact form.
pub const POW_LIMIT_BITS: u32 = 0x1d00_ffff;

/// `SHA256(SHA256(data))`.
#[must_use]
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let once = Sha256::digest(data);
    Sha256::digest(once).into()
}

/// SipHash-2-4 (Aumasson–Bernstein), the keyed hash BIP 158 maps each item with.
#[must_use]
pub fn siphash24(k0: u64, k1: u64, msg: &[u8]) -> u64 {
    let mut v = [k0 ^ 0x736f_6d65_7073_6575, k1 ^ 0x646f_7261_6e64_6f6d, k0 ^ 0x6c79_6765_6e65_7261, k1 ^ 0x7465_6462_7974_6573];
    fn round(v: &mut [u64; 4]) {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13) ^ v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16) ^ v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21) ^ v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17) ^ v[2];
        v[2] = v[2].rotate_left(32);
    }
    let mut chunks = msg.chunks_exact(8);
    for c in &mut chunks {
        let m = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
        v[3] ^= m;
        round(&mut v);
        round(&mut v);
        v[0] ^= m;
    }
    let mut last = [0u8; 8];
    last[..chunks.remainder().len()].copy_from_slice(chunks.remainder());
    last[7] = msg.len() as u8;
    let m = u64::from_le_bytes(last);
    v[3] ^= m;
    round(&mut v);
    round(&mut v);
    v[0] ^= m;
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// Bitcoin's CompactSize integer at `*at`, advancing it.
fn compact_size(b: &[u8], at: &mut usize) -> Option<u64> {
    let first = *b.get(*at)?;
    let (len, v) = match first {
        0xfd => (2, u64::from(u16::from_le_bytes(b.get(*at + 1..*at + 3)?.try_into().ok()?))),
        0xfe => (4, u64::from(u32::from_le_bytes(b.get(*at + 1..*at + 5)?.try_into().ok()?))),
        0xff => (8, u64::from_le_bytes(b.get(*at + 1..*at + 9)?.try_into().ok()?)),
        n => (0, u64::from(n)),
    };
    *at += 1 + len;
    Some(v)
}

/// A filter's decoded content: `n` and the sorted mapped values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    pub n: u64,
    pub values: Vec<u64>,
}

/// ⭐ Decode a BIP 158 filter. `None` for a malformed one. The element count is bounded by the bits present (each
/// element takes at least `P + 1` bits), so a hostile count cannot make the decoder work past the bytes it was sent.
#[must_use]
pub fn decode(filter: &[u8]) -> Option<Filter> {
    let mut at = 0;
    let n = compact_size(filter, &mut at)?;
    let body = &filter[at..];
    if n > (body.len() as u64 * 8) / u64::from(P + 1) {
        return None;
    }
    let mut bit = 0usize;
    let total = body.len() * 8;
    let mut read = |count: u32| -> Option<u64> {
        let mut v = 0u64;
        for _ in 0..count {
            if bit >= total {
                return None;
            }
            v = (v << 1) | u64::from((body[bit / 8] >> (7 - bit % 8)) & 1);
            bit += 1;
        }
        Some(v)
    };
    let mut values = Vec::with_capacity(n as usize);
    let mut last = 0u64;
    for _ in 0..n {
        let mut q = 0u64;
        while read(1)? == 1 {
            q += 1;
        }
        let r = read(P)?;
        last = last.checked_add((q << P) | r)?;
        values.push(last);
    }
    Some(Filter { n, values })
}

/// The SipHash key BIP 158 uses: the first 16 bytes of the block hash in its internal (little-endian) order.
fn key_of(block_hash: &[u8; 32]) -> (u64, u64) {
    let k0 = u64::from_le_bytes(block_hash[0..8].try_into().map_or([0; 8], |a| a));
    let k1 = u64::from_le_bytes(block_hash[8..16].try_into().map_or([0; 8], |a| a));
    (k0, k1)
}

/// An item's value in `[0, n·M)`.
fn mapped(block_hash: &[u8; 32], n: u64, item: &[u8]) -> u64 {
    let (k0, k1) = key_of(block_hash);
    ((u128::from(siphash24(k0, k1, item)) * u128::from(n.saturating_mul(M))) >> 64) as u64
}

/// ⭐ Does the block's filter match any of `scripts`? `None` for a malformed filter. A match means "fetch the block and
/// read it" (false positives at 1 / M per script); no match means no watched script is in the block.
#[must_use]
pub fn matches_any(block_hash: &[u8; 32], filter: &[u8], scripts: &[&[u8]]) -> Option<bool> {
    let f = decode(filter)?;
    if f.n == 0 {
        return Some(false);
    }
    Some(scripts.iter().any(|s| f.values.binary_search(&mapped(block_hash, f.n, s)).is_ok()))
}

/// ⭐ Encode a BIP 158 basic filter over `elements` (each once): the CompactSize count, then the sorted mapped values'
/// deltas Golomb-Rice coded with P = 19, most significant bit first — exactly what `decode` reads.
#[must_use]
pub fn encode(block_hash: &[u8; 32], elements: &[Vec<u8>]) -> Vec<u8> {
    let n = elements.len() as u64;
    let mut out = Vec::new();
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
    let mut vals: Vec<u64> = elements.iter().map(|e| mapped(block_hash, n, e)).collect();
    vals.sort_unstable();
    let (mut acc, mut nbits) = (0u8, 0u8);
    let mut put = |bit: u8, out: &mut Vec<u8>| {
        acc = (acc << 1) | bit;
        nbits += 1;
        if nbits == 8 {
            out.push(acc);
            acc = 0;
            nbits = 0;
        }
    };
    let mut last = 0u64;
    for v in vals {
        let d = v - last;
        last = v;
        for _ in 0..(d >> P) {
            put(1, &mut out);
        }
        put(0, &mut out);
        for i in (0..P).rev() {
            put(((d >> i) & 1) as u8, &mut out);
        }
    }
    if nbits > 0 {
        out.push(acc << (8 - nbits));
    }
    out
}

/// The BIP 157 filter header: `dSHA256(dSHA256(filter) ‖ previous filter header)`, both in internal byte order.
#[must_use]
pub fn filter_header(filter: &[u8], prev: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&sha256d(filter));
    buf[32..].copy_from_slice(prev);
    sha256d(&buf)
}

/// A 256-bit unsigned number, little-endian bytes (Bitcoin's `arith_uint256` for the shifts and scalings PoW needs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct U256([u8; 32]);

impl U256 {
    fn bits(&self) -> u32 {
        for i in (0..32).rev() {
            if self.0[i] != 0 {
                return i as u32 * 8 + (8 - self.0[i].leading_zeros());
            }
        }
        0
    }
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.0.iter().rev().cmp(o.0.iter().rev())
    }
    /// `None` on overflow past 256 bits.
    fn mul_u64(&self, m: u64) -> Option<Self> {
        let mut out = [0u8; 32];
        let mut carry = 0u128;
        for i in 0..32 {
            carry += u128::from(self.0[i]) * u128::from(m);
            out[i] = (carry & 0xff) as u8;
            carry >>= 8;
        }
        (carry == 0).then_some(U256(out))
    }
    fn div_u64(&self, d: u64) -> Self {
        let mut out = [0u8; 32];
        let mut rem = 0u128;
        for i in (0..32).rev() {
            rem = (rem << 8) | u128::from(self.0[i]);
            out[i] = (rem / u128::from(d)) as u8;
            rem %= u128::from(d);
        }
        U256(out)
    }
    /// `self + 1`; `None` past 256 bits.
    fn add_one(&self) -> Option<Self> {
        let mut out = self.0;
        for b in &mut out {
            let (v, c) = b.overflowing_add(1);
            *b = v;
            if !c {
                return Some(U256(out));
            }
        }
        None
    }
    /// Long division by a nonzero divisor (shift-subtract over 256 bits).
    fn div(&self, d: &Self) -> Self {
        let mut q = [0u8; 32];
        let mut r = U256([0u8; 32]);
        for bit in (0..256).rev() {
            // r = r << 1 | bit of self
            let mut carry = (self.0[bit / 8] >> (bit % 8)) & 1;
            for b in &mut r.0 {
                let next = *b >> 7;
                *b = (*b << 1) | carry;
                carry = next;
            }
            if carry == 1 || r.cmp(d) != std::cmp::Ordering::Less {
                let mut borrow = 0i16;
                for i in 0..32 {
                    let v = i16::from(r.0[i]) - i16::from(d.0[i]) - borrow;
                    borrow = i16::from(v < 0);
                    r.0[i] = v.rem_euclid(256) as u8;
                }
                q[bit / 8] |= 1 << (bit % 8);
            }
        }
        U256(q)
    }
    fn low_u128(&self) -> u128 {
        if self.0[16..].iter().any(|b| *b != 0) {
            return u128::MAX;
        }
        u128::from_le_bytes(self.0[..16].try_into().map_or([0; 16], |a| a))
    }
    /// `arith_uint256::SetCompact`: `None` for a negative or overflowing encoding.
    fn from_compact(c: u32) -> Option<Self> {
        let size = (c >> 24) as usize;
        let mut word = c & 0x007f_ffff;
        let mut out = [0u8; 32];
        if size <= 3 {
            word >>= 8 * (3 - size as u32);
            out[..4].copy_from_slice(&word.to_le_bytes());
        } else {
            let wb = word.to_le_bytes();
            for (j, b) in wb.iter().take(3).enumerate() {
                if *b != 0 && size - 3 + j >= 32 {
                    return None; // overflow
                }
                if size - 3 + j < 32 {
                    out[size - 3 + j] = *b;
                }
            }
        }
        if word != 0 && c & 0x0080_0000 != 0 {
            return None; // negative
        }
        Some(U256(out))
    }
    /// `arith_uint256::GetCompact`.
    fn to_compact(&self) -> u32 {
        let mut size = self.bits().div_ceil(8);
        let low = |from: usize| -> u32 {
            let mut v = 0u32;
            for j in (0..3).rev() {
                v = (v << 8) | u32::from(*self.0.get(from + j).map_or(&0, |b| b));
            }
            v
        };
        let mut compact = if size <= 3 { low(0) << (8 * (3 - size)) } else { low(size as usize - 3) };
        if compact & 0x0080_0000 != 0 {
            compact >>= 8;
            size += 1;
        }
        compact | (size << 24)
    }
}

/// The block header's hash (internal byte order).
#[must_use]
pub fn header_hash(header: &[u8; 80]) -> [u8; 32] {
    sha256d(header)
}

/// The `nBits` field of an 80-byte header.
#[must_use]
pub fn header_bits(header: &[u8; 80]) -> u32 {
    u32::from_le_bytes([header[72], header[73], header[74], header[75]])
}

/// ⭐ Bitcoin's `CheckProofOfWork`: the header's hash is at or under the target its `nBits` declares, and that target is
/// a valid, positive encoding at or under the proof-of-work limit. (Whether `nBits` is the RIGHT difficulty for its height
/// is [`next_bits`]'s rule, checked across the header chain by [`HeaderFollower`].)
#[must_use]
pub fn header_pow_ok(header: &[u8; 80]) -> bool {
    pow_ok_under(header, POW_LIMIT_BITS)
}

fn pow_ok_under(header: &[u8; 80], limit_bits: u32) -> bool {
    let (Some(target), Some(limit)) = (U256::from_compact(header_bits(header)), U256::from_compact(limit_bits)) else {
        return false;
    };
    if target.bits() == 0 || target.cmp(&limit) == std::cmp::Ordering::Greater {
        return false;
    }
    U256(header_hash(header)).cmp(&target) != std::cmp::Ordering::Greater
}

/// ⭐ Bitcoin's `CalculateNextWorkRequired` (Bitcoin Core `pow.cpp`): the `nBits` of the block after a retarget period whose
/// first block was timestamped `first_time` and whose last carries `last_bits` at `last_time`.
#[must_use]
pub fn next_bits(last_bits: u32, first_time: i64, last_time: i64) -> u32 {
    next_bits_under(&MAINNET, last_bits, first_time, last_time)
}

fn next_bits_under(p: &Params, last_bits: u32, first_time: i64, last_time: i64) -> u32 {
    let span = (last_time - first_time).clamp(p.timespan / 4, p.timespan * 4);
    let (Some(old), Some(limit)) = (U256::from_compact(last_bits), U256::from_compact(p.pow_limit_bits)) else {
        return p.pow_limit_bits;
    };
    let new = old.mul_u64(span as u64).map_or(limit, |x| x.div_u64(p.timespan as u64));
    if new.cmp(&limit) == std::cmp::Ordering::Greater { limit.to_compact() } else { new.to_compact() }
}

/// A header's work, `2^256 / (target + 1)` (Bitcoin Core `GetBlockProof`), saturated into a u128 (mainnet's per-block work
/// is ~2^80, so a ring's sum never saturates). 0 for an invalid target.
fn header_work(bits: u32) -> u128 {
    let Some(t) = U256::from_compact(bits) else { return 0 };
    if t.bits() == 0 {
        return 0;
    }
    // (~t / (t + 1)) + 1, as GetBlockProof computes it
    let mut not = t;
    for b in &mut not.0 {
        *b = !*b;
    }
    let Some(t1) = t.add_one() else { return 1 };
    let q = not.div(&t1);
    q.low_u128().saturating_add(1)
}

/// The chain rules a [`HeaderFollower`] enforces (Bitcoin Core `chainparams.cpp` values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub pow_limit_bits: u32,
    /// Blocks per difficulty period.
    pub interval: u32,
    pub timespan: i64,
    /// The lowest header version the follower's heights accept (BIP 34/66/65 activated long before any checkpoint).
    pub min_version: i32,
    /// A test network's exception (`fPowAllowMinDifficultyBlocks`): off a boundary, a block more than two target spacings
    /// after its parent may carry the proof-of-work limit.
    pub allow_min_difficulty: bool,
    /// BIP 94 (testnet4): the retarget starts from the period's FIRST block's difficulty (a min-difficulty last block cannot
    /// drag it), and a period's first block may not be more than ten minutes before its parent (the timewarp fix).
    pub bip94: bool,
}

/// Bitcoin mainnet.
pub const MAINNET: Params =
    Params { pow_limit_bits: POW_LIMIT_BITS, interval: 2016, timespan: TARGET_TIMESPAN, min_version: 4, allow_min_difficulty: false, bip94: false };
/// Bitcoin testnet4 (Bitcoin Core `CTestNet4Params`: BIP 94 enforced, min-difficulty blocks allowed).
pub const TESTNET4: Params =
    Params { pow_limit_bits: POW_LIMIT_BITS, interval: 2016, timespan: TARGET_TIMESPAN, min_version: 4, allow_min_difficulty: true, bip94: true };
/// BIP 94's `MAX_TIMEWARP`: a period's first block at most this far before its parent.
pub const MAX_TIMEWARP_SECS: u32 = 600;

/// Headers kept for reorgs: one day of blocks. A reorg deeper than this is refused (the bridge counts a deposit only
/// far shallower than a day).
pub const RING: usize = 144;
/// A header more than this far past the local clock is refused (Bitcoin Core `MAX_FUTURE_BLOCK_TIME`).
pub const MAX_FUTURE_SECS: u64 = 2 * 60 * 60;

/// One followed header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub hash: [u8; 32],
    pub height: u32,
    pub bits: u32,
    pub time: u32,
    /// The timestamp of the first block of this header's difficulty period.
    pub period_first_time: u32,
    /// The difficulty the period's first block carries — the period's real difficulty (a test network's min-difficulty
    /// blocks are exceptions to it, never a new one).
    pub period_bits: u32,
    /// Work summed since the follower's checkpoint.
    pub work: u128,
}

/// Where a follower starts: a header the release trusts by its hash (as Bitcoin Core's assumevalid / Neutrino's
/// checkpoints), with the eleven timestamps ending at it for the median-time rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub hash: [u8; 32],
    pub height: u32,
    pub bits: u32,
    pub period_first_time: u32,
    /// The difficulty of the checkpoint's period's first block.
    pub period_bits: u32,
    /// The timestamps of the eleven headers ending at the checkpoint, oldest first.
    pub times: [u32; 11],
}

/// Why a batch of headers was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The first header's parent is not a header this follower holds (or is older than its ring).
    UnknownParent,
    /// Two headers of the batch do not link.
    Unlinked,
    Version,
    /// `nBits` is not the difficulty the chain's rule sets for that height.
    WrongDifficulty,
    ProofOfWork,
    /// Timestamp at or below the median of the previous eleven.
    TimeTooOld,
    TimeTooNew,
}

/// ⭐ §22 6 — THE HEADER-CHAIN FOLLOWER: Bitcoin's header rules (`CheckBlockHeader` + `ContextualCheckBlockHeader`) applied
/// by the node itself, most work wins (Bitcoin's chain selection), in constant state: the last [`RING`] headers and the
/// eleven timestamps before them. O1-FOOTPRINT-REVIEWED: ≤ RING entries of 76 bytes + 44 bytes, whatever the height.
#[derive(Clone, Debug)]
pub struct HeaderFollower {
    params: Params,
    ring: std::collections::VecDeque<Entry>,
    /// The timestamps before `ring[0]`, oldest first (eleven at most).
    before: std::collections::VecDeque<u32>,
}

impl HeaderFollower {
    #[must_use]
    pub fn new(params: Params, cp: Checkpoint) -> Self {
        let mut ring = std::collections::VecDeque::with_capacity(RING + 1);
        let entry = Entry {
            hash: cp.hash,
            height: cp.height,
            bits: cp.bits,
            time: cp.times[10],
            period_first_time: cp.period_first_time,
            period_bits: cp.period_bits,
            work: 0,
        };
        ring.push_back(entry);
        HeaderFollower { params, ring, before: cp.times[..10].iter().copied().collect() }
    }

    /// The oldest header the follower still holds (the start of its one-day ring) — where a filter re-check begins.
    #[must_use]
    pub fn oldest(&self) -> Entry {
        self.ring[0]
    }

    /// The most-work tip.
    #[must_use]
    pub fn tip(&self) -> Entry {
        self.ring[self.ring.len() - 1]
    }

    /// How many headers of the most-work chain sit on `hash` (1 = it is the tip); `None` if it is not on that chain within
    /// the ring.
    #[must_use]
    pub fn confirmations(&self, hash: &[u8; 32]) -> Option<u32> {
        let tip = self.tip().height;
        self.ring.iter().find(|e| &e.hash == hash).map(|e| tip - e.height + 1)
    }

    /// The eleven timestamps ending at ring index `i`.
    fn last11(&self, i: usize) -> Vec<u32> {
        let mut t: Vec<u32> = self.before.iter().copied().chain(self.ring.iter().take(i + 1).map(|e| e.time)).collect();
        let cut = t.len().saturating_sub(11);
        t.drain(..cut);
        t
    }

    /// ⭐ Accept a batch of linked headers whose first extends a header this follower holds: every header is checked
    /// against its parent's context; the batch becomes the chain when it extends the tip or carries MORE work than the
    /// headers it would replace. `Ok(true)` = the tip moved, `Ok(false)` = valid but less work (kept out).
    pub fn accept(&mut self, headers: &[[u8; 80]], now_secs: u64) -> Result<bool, Refusal> {
        let Some(first) = headers.first() else { return Ok(false) };
        let parent = self.ring.iter().position(|e| e.hash[..] == first[4..36]).ok_or(Refusal::UnknownParent)?;
        let mut times = self.last11(parent);
        let mut prev = self.ring[parent];
        let mut branch = Vec::with_capacity(headers.len());
        for h in headers {
            if h[4..36] != prev.hash[..] {
                return Err(Refusal::Unlinked);
            }
            let version = i32::from_le_bytes([h[0], h[1], h[2], h[3]]);
            let time = u32::from_le_bytes([h[68], h[69], h[70], h[71]]);
            let bits = header_bits(h);
            let height = prev.height + 1;
            if version < self.params.min_version {
                return Err(Refusal::Version);
            }
            let boundary = height % self.params.interval == 0;
            // Bitcoin Core `GetNextWorkRequired`: a boundary retargets (BIP 94: from the period's first difficulty); off a
            // boundary the period's difficulty holds, except a test network's block > 2 spacings after its parent, which may
            // carry the limit
            let want = if boundary {
                let base = if self.params.bip94 { prev.period_bits } else { prev.bits };
                next_bits_under(&self.params, base, i64::from(prev.period_first_time), i64::from(prev.time))
            } else {
                prev.period_bits
            };
            let spacing = (self.params.timespan / i64::from(self.params.interval)) as u32;
            let min_ok = self.params.allow_min_difficulty
                && !boundary
                && time > prev.time.saturating_add(2 * spacing)
                && bits == self.params.pow_limit_bits;
            if bits != want && !min_ok {
                return Err(Refusal::WrongDifficulty);
            }
            if self.params.bip94 && boundary && time < prev.time.saturating_sub(MAX_TIMEWARP_SECS) {
                return Err(Refusal::TimeTooOld); // BIP 94: the timewarp attack
            }
            if !pow_ok_under(h, self.params.pow_limit_bits) {
                return Err(Refusal::ProofOfWork);
            }
            let mut sorted = times.clone();
            sorted.sort_unstable();
            if time <= sorted[sorted.len() / 2] {
                return Err(Refusal::TimeTooOld);
            }
            if u64::from(time) > now_secs.saturating_add(MAX_FUTURE_SECS) {
                return Err(Refusal::TimeTooNew);
            }
            let e = Entry {
                hash: header_hash(h),
                height,
                bits,
                time,
                period_first_time: if boundary { time } else { prev.period_first_time },
                period_bits: if boundary { bits } else { prev.period_bits },
                work: prev.work.saturating_add(header_work(bits)),
            };
            times.push(time);
            if times.len() > 11 {
                times.remove(0);
            }
            branch.push(e);
            prev = e;
        }
        if prev.work <= self.tip().work {
            return Ok(false); // a branch with no more work than the chain it would replace stays out (first seen wins a tie)
        }
        self.ring.truncate(parent + 1);
        for e in branch {
            self.ring.push_back(e);
            while self.ring.len() > RING {
                if let Some(old) = self.ring.pop_front() {
                    self.before.push_back(old.time);
                    while self.before.len() > 10 {
                        self.before.pop_front();
                    }
                }
            }
        }
        Ok(true)
    }
}

/// What the peers' answers for one height add up to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Agreement {
    /// ≥ [`MIN_FILTER_PEERS`] distinct peers report this value and none reports another.
    Agreed([u8; 32]),
    /// Too few distinct peers yet: ask more, count nothing.
    Wait,
    /// Two values were reported: nothing counts by majority; the watcher asks other peers (BIP 157's client rule).
    Conflict,
}

/// ⭐ §22 6 — the agreement rule over `(peer, value)` answers for one height (a filter header for Bitcoin, a block hash for
/// Monero's daemons): a peer answering twice counts once, and any second value is a conflict.
#[must_use]
pub fn agree(answers: &[([u8; 32], [u8; 32])]) -> Agreement {
    let Some(first) = answers.first().map(|a| a.1) else { return Agreement::Wait };
    if answers.iter().any(|a| a.1 != first) {
        return Agreement::Conflict;
    }
    let mut peers: Vec<[u8; 32]> = answers.iter().map(|a| a.0).collect();
    peers.sort_unstable();
    peers.dedup();
    if peers.len() >= MIN_FILTER_PEERS { Agreement::Agreed(first) } else { Agreement::Wait }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
    }
    /// A display-order hash as the internal bytes.
    fn internal(s: &str) -> [u8; 32] {
        let mut v = unhex(s);
        v.reverse();
        v.try_into().expect("32 bytes")
    }

    /// Bitcoin Core `src/test/data/blockfilters.json` (BIP 158's own vectors, testnet3): (height, block hash, the block's
    /// 80-byte header, previous-output scripts, previous filter header, basic filter, filter header) — hex, display order
    /// for hashes as the file gives them.
    const VECTORS: &[(u32, &str, &str, &[&str], &str, &str, &str)] = &[
        (0, "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943", "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18", &[], "0000000000000000000000000000000000000000000000000000000000000000", "019dfca8", "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750"),
        (2, "000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820", "0100000006128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000e241352e3bec0a95a6217e10c3abb54adfa05abb12c126695595580fb92e222032e7494dffff001d00d23534", &[], "d7bdac13a59d745b1add0d2ce852f1a0442e8945fc1bf3848d3cbffd88c24fe1", "0174a170", "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0"),
        (3, "000000008b896e272758da5297bcd98fdc6d97c9b765ecec401e286dc1fdbe10", "0100000020782a005255b657696ea057d5b98f34defcf75196f64f6eeac8026c0000000041ba5afc532aae03151b8aa87b65e1594f97504a768e010c98c0add79216247186e7494dffff001d058dc2b6", &[], "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0", "016cf7a0", "8d63aadf5ab7257cb6d2316a57b16f517bff1c6388f124ec4c04af1212729d2a"),
        (15007, "0000000038c44c703bae0f98cdd6bf30922326340a5996cc692aaae8bacf47ad", "0100000002394092aa378fe35d7e9ac79c869b975c4de4374cd75eb5484b0e1e00000000eb9b8670abd44ad6c55cee18e3020fb0c6519e7004b01a16e9164867531b67afc33bc94fffff001d123f1005", &[], "18b5c2b0146d2d09d24fb00ff5b52bd0742f36c9e65527abdb9de30c027a4748", "013c3710", "07384b01311867949e0c046607c66b7a766d338474bb67f66c8ae9dbd454b20e"),
        (49291, "0000000018b07dca1b28b4b5a119f6d6e71698ce1ed96f143f54179ce177a19c", "02000000abfaf47274223ca2fea22797e44498240e482cb4c2f2baea088962f800000000604b5b52c32305b15d7542071d8b04e750a547500005d4010727694b6e72a776e55d0d51ffff001d21180648", &["5221033423007d8f263819a2e42becaaf5b06f34cb09919e06304349d950668209eaed21021d69e2b68c3960903b702af7829fadcd80bd89b158150c85c4a75b2c8cb9c39452ae", "52210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821021d69e2b68c3960903b702af7829fadcd80bd89b158150c85c4a75b2c8cb9c39452ae", "522102a7ae1e0971fc1689bd66d2a7296da3a1662fd21a53c9e38979e0f090a375c12d21022adb62335f41eb4e27056ac37d462cda5ad783fa8e0e526ed79c752475db285d52ae", "52210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821022adb62335f41eb4e27056ac37d462cda5ad783fa8e0e526ed79c752475db285d52ae", "512103b9d1d0e2b4355ec3cdef7c11a5c0beff9e8b8d8372ab4b4e0aaf30e80173001951ae", "76a9149144761ebaccd5b4bbdc2a35453585b5637b2f8588ac", "522103f1848b40621c5d48471d9784c8174ca060555891ace6d2b03c58eece946b1a9121020ee5d32b54d429c152fdc7b1db84f2074b0564d35400d89d11870f9273ec140c52ae", "76a914f4fa1cc7de742d135ea82c17adf0bb9cf5f4fb8388ac"], "ed47705334f4643892ca46396eb3f4196a5e30880589e4009ef38eae895d4a13", "0afbc2920af1b027f31f87b592276eb4c32094bb4d3697021b4c6380", "b6d98692cec5145f67585f3434ec3c2b3030182e1cb3ec58b855c5c164dfaaa3"),
        (180480, "00000000fd3ceb2404ff07a785c7fdcc76619edc8ed61bd25134eaa22084366a", "020000006058aa080a655aa991a444bd7d1f2defd9a3bbe68aabb69030cf3b4e00000000d2e826bfd7ef0beaa891a7eedbc92cd6a544a6cb61c7bdaa436762eb2123ef9790f5f552ffff001d0002c90f", &["", "", "", "76a9142903b138c24be9e070b3e73ec495d77a204615e788ac", "76a91433a1941fd9a37b9821d376f5a51bd4b52fa50e2888ac", "76a914e4374e8155d0865742ca12b8d4d14d41b57d682f88ac", "76a914001fa7459a6cfc64bdc178ba7e7a21603bb2568f88ac", "76a914f6039952bc2b307aeec5371bfb96b66078ec17f688ac"], "d34ef98386f413769502808d4bac5f20f8dfd5bffc9eedafaa71de0eb1f01489", "0db414c859a07e8205876354a210a75042d0463404913d61a8e068e58a3ae2aa080026", "c582d51c0ca365e3fcf36c51cb646d7f83a67e867cb4743fd2128e3e022b700c"),
        (926485, "000000000000015d6077a411a8f5cc95caf775ccf11c54e27df75ce58d187313", "0000002060bbab0edbf3ef8a49608ee326f8fd75c473b7e3982095e2d100000000000000c30134f8c9b6d2470488d7a67a888f6fa12f8692e0c3411fbfb92f0f68f67eedae03ca57ef13021acc22dc41", &["a914feb8a29635c56d9cd913122f90678756bf23887687", "76a914c01a7ca16b47be50cbdbc60724f701d52d75156688ac", "76a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac", "76a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac", "76a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac", "76a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac", "76a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac", "76a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac"], "8f13b9a9c85611635b47906c3053ac53cfcec7211455d4cb0d63dc9acc13d472", "09027acea61b6cc3fb33f5d52f7d088a6b2f75d234e89ca800", "546c574a0472144bcaf9b6aeabf26372ad87c7af7d1ee0dbfae5e099abeae49c"),
        (987876, "0000000000000c00901f2049055e2a437c819d79a3d54fd63e6af796cd7b8a79", "000000202694f74969fdb542090e95a56bc8aa2d646e27033850e32f1c5f000000000000f7e53676b3f12d5beb524ed617f2d25f5a93b5f4f52c1ba2678260d72712f8dd0a6dfe5740257e1a4b176896", &[], "fe4d230dbb0f4fec9bed23a5283e08baf996e3f32b93f52c7de1f641ddfd04ad", "010c0b40", "0965a544743bbfa36f254446e75630c09404b3d164a261892372977538928ed5"),
        (1263442, "000000006f27ddfe1dd680044a34548f41bed47eba9e6f0b310da21423bc5f33", "000000201c8d1a529c39a396db2db234d5ec152fa651a2872966daccbde028b400000000083f14492679151dbfaa1a825ef4c18518e780c1f91044180280a7d33f4a98ff5f45765aaddc001d38333b9a", &["002027a5000c7917f785d8fc6e5a55adfca8717ecb973ebb7743849ff956d896a7ed"], "31d66d516a9eda7de865df29f6ef6cb8e4bf9309e5dac899968a9a62a5df61e3", "0385acb4f0fe889ef0", "4e6d564c2a2452065c205dd7eb2791124e0c4e0dbb064c410c24968572589dec"),
        (1414221, "0000000000000027b2b3b3381f114f674f481544ff2be37ae3788d7e078383b1", "000000204ea88307a7959d8207968f152bedca5a93aefab253f1fb2cfb032a400000000070cebb14ec6dbc27a9dfd066d9849a4d3bac5f674665f73a5fe1de01a022a0c851fda85bf05f4c19a779d145", &[], "5e5e12d90693c8e936f01847859404c67482439681928353ca1296982042864e", "00", "021e8882ef5a0ed932edeebbecfeda1d7ce528ec7b3daa27641acf1189d7b5dc"),
    ];

    /// SipHash-2-4's reference vector (the paper's Appendix A: key 00..0f, message 00..0e).
    #[test]
    fn siphash_matches_the_reference_vector() {
        let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
        let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
        let msg: Vec<u8> = (0u8..15).collect();
        assert_eq!(siphash24(k0, k1, &msg), 0xa129_ca61_49be_45e5);
    }

    /// ⭐⭐⭐ §22 6 — every BIP 158 vector: the header's proof of work holds and hashes to the block hash, the filter header
    /// chains from the previous one exactly, and every previous-output script the block spends matches its filter.
    #[test]
    fn btc_filters_match_bitcoin_cores_own_vectors() {
        let mut checked_scripts = 0;
        for (height, hash, header, scripts, prev, filter, fheader) in VECTORS {
            let h: [u8; 80] = unhex(header).try_into().expect("80-byte header");
            assert_eq!(header_hash(&h), internal(hash), "height {height}: the header hashes to the block hash");
            assert!(header_pow_ok(&h), "height {height}: proof of work holds");
            let f = unhex(filter);
            assert_eq!(filter_header(&f, &internal(prev)), internal(fheader), "height {height}: filter header chain");
            let block = internal(hash);
            let decoded = decode(&f).expect("a valid filter decodes");
            assert_eq!(decoded.values.len() as u64, decoded.n);
            for s in *scripts {
                if s.is_empty() {
                    continue; // BIP 158 excludes empty scripts
                }
                assert_eq!(matches_any(&block, &f, &[&unhex(s)]), Some(true), "height {height}: a spent script matches");
                checked_scripts += 1;
            }
            let stranger = b"\x00\x14a script this block never touched";
            if decoded.n > 0 {
                assert_eq!(matches_any(&block, &f, &[stranger]), Some(false), "height {height}: a stranger does not match");
            }
        }
        assert!(checked_scripts >= 20, "the vectors exercise real scripts ({checked_scripts})");
    }

    /// Tampering refuses: a header whose nonce moved fails its proof of work; a filter with a flipped byte breaks the
    /// header chain; a filter claiming more elements than its bits can hold, or cut short, does not decode.
    #[test]
    fn a_tampered_header_or_filter_is_refused() {
        let (_, _, header, _, prev, filter, fheader) = VECTORS[4];
        let mut h: [u8; 80] = unhex(header).try_into().expect("80");
        h[76] ^= 1;
        assert!(!header_pow_ok(&h), "a moved nonce misses the target");
        let mut f = unhex(filter);
        let last = f.len() - 1;
        f[last] ^= 1;
        assert_ne!(filter_header(&f, &internal(prev)), internal(fheader), "a flipped filter byte breaks the chain");
        assert!(decode(&[0xfd, 0xff, 0xff, 0x00]).is_none(), "65535 elements in 1 byte is refused before any work");
        let good = unhex(filter);
        assert!(decode(&good[..good.len() - 2]).is_none(), "a truncated filter is refused");
        let mut easy = h;
        easy[72..76].copy_from_slice(&0x2100_ffffu32.to_le_bytes());
        assert!(!header_pow_ok(&easy), "a target above the proof-of-work limit is refused");
    }

    /// ⭐ Bitcoin Core's own `pow_tests.cpp` cases for the retarget, verbatim.
    #[test]
    fn btc_retarget_matches_bitcoin_cores_pow_tests() {
        assert_eq!(next_bits(0x1d00ffff, 1_261_130_161, 1_262_152_739), 0x1d00d86a, "get_next_work (#32255)");
        assert_eq!(next_bits(0x1d00ffff, 1_231_006_505, 1_233_061_996), 0x1d00ffff, "get_next_work_pow_limit");
        assert_eq!(next_bits(0x1c05a3f4, 1_279_008_237, 1_279_297_671), 0x1c0168fd, "lower_limit_actual");
        assert_eq!(next_bits(0x1c05a3f4, 1_279_297_671, 1_279_008_237), 0x1c0168fd, "a negative span clamps to a quarter");
        assert_eq!(next_bits(0x1c387f6f, 1_263_163_443, 1_269_211_443), 0x1d00e1fd, "upper_limit_actual");
    }

    /// Easy proof of work with a short period, so a test mines headers in microseconds; every RULE is mainnet's. The limit
    /// (~2^251) times the largest clamped span (4 × 8) stays inside 256 bits, as mainnet's (~2^224 × 4 × two weeks) does —
    /// regtest's 0x207fffff would overflow, which is why Bitcoin Core turns retargeting off there.
    const EASY: Params =
        Params { pow_limit_bits: 0x2007_ffff, interval: 8, timespan: 8, min_version: 4, allow_min_difficulty: false, bip94: false };
    /// One second per block: the target spacing of `EASY`.
    const SPACING: u32 = 1;
    const T0: u32 = 1_700_000_000;

    fn header(prev: &[u8; 32], time: u32, bits: u32, tag: u8, version: i32, nonce: u32) -> [u8; 80] {
        let mut h = [0u8; 80];
        h[0..4].copy_from_slice(&version.to_le_bytes());
        h[4..36].copy_from_slice(prev);
        h[36] = tag;
        h[68..72].copy_from_slice(&time.to_le_bytes());
        h[72..76].copy_from_slice(&bits.to_le_bytes());
        h[76..80].copy_from_slice(&nonce.to_le_bytes());
        h
    }
    fn mine(prev: &[u8; 32], time: u32, bits: u32, tag: u8) -> [u8; 80] {
        (0u32..).map(|n| header(prev, time, bits, tag, 4, n)).find(|h| pow_ok_under(h, EASY.pow_limit_bits)).expect("mined")
    }
    fn follower() -> HeaderFollower {
        let times: [u32; 11] = std::array::from_fn(|i| T0 - SPACING * (10 - i as u32));
        HeaderFollower::new(
            EASY,
            Checkpoint { hash: [0x11; 32], height: 0, bits: EASY.pow_limit_bits, period_first_time: T0, period_bits: EASY.pow_limit_bits, times },
        )
    }
    /// Mine `n` headers from `parent` (an entry) at `SPACING` — a little faster than the period expects, so every boundary
    /// raises the difficulty — each with the difficulty the rule sets.
    fn chain(parent: Entry, n: usize, tag: u8) -> Vec<[u8; 80]> {
        let mut out = Vec::new();
        let (mut prev, mut bits, mut first) = (parent.hash, parent.bits, parent.period_first_time);
        let mut time = parent.time;
        for i in 0..n {
            let height = parent.height + 1 + i as u32;
            let prev_time = time;
            time += SPACING;
            if height % EASY.interval == 0 {
                bits = next_bits_under(&EASY, bits, i64::from(first), i64::from(prev_time));
                first = time;
            }
            let h = mine(&prev, time, bits, tag);
            prev = header_hash(&h);
            out.push(h);
        }
        out
    }

    /// Bitcoin's genesis difficulty does 0x100010001 work per block (the chainwork every explorer shows for block 0).
    #[test]
    fn header_work_matches_bitcoins_genesis_chainwork() {
        assert_eq!(header_work(0x1d00_ffff), 0x1_0001_0001);
        assert_eq!(header_work(0x0100_0000), 0, "a zero target does no work");
    }

    /// ⭐⭐⭐ §22 6 — THE FOLLOWER TAKES A VALID CHAIN ACROSS DIFFICULTY PERIODS and counts confirmations on it.
    #[test]
    fn the_header_follower_follows_a_valid_chain_across_retargets() {
        let mut f = follower();
        let hs = chain(f.tip(), 30, 1);
        assert_eq!(f.accept(&hs[..5], u64::from(T0) + 100_000), Ok(true));
        assert_eq!(f.accept(&hs[5..], u64::from(T0) + 100_000), Ok(true));
        assert_eq!(f.tip().height, 30);
        assert_eq!(f.tip().hash, header_hash(&hs[29]));
        assert_ne!(f.tip().bits, EASY.pow_limit_bits, "spacing below target raised the difficulty at the boundaries");
        assert_eq!(f.confirmations(&header_hash(&hs[27])), Some(3));
        assert_eq!(f.confirmations(&[0xEE; 32]), None);
    }

    /// ⭐⭐⭐ §22 6 — every header rule refuses its tamper: an unknown parent, an unlinked batch, a version below the floor, a
    /// difficulty the rule did not set (off a boundary, and the old difficulty kept across one), a hash over its target, a
    /// timestamp at the median of the last eleven, one more than two hours ahead — and a refused batch moves nothing.
    #[test]
    fn the_header_follower_refuses_every_rule_break() {
        let now = u64::from(T0) + 100_000;
        let mut f = follower();
        let good = chain(f.tip(), 7, 1);
        f.accept(&good, now).expect("seven valid headers");
        let tip = f.tip();
        let t = tip.time + 600;
        // height 8 is a boundary: the difficulty the rule sets there
        let right = next_bits_under(&EASY, tip.bits, i64::from(tip.period_first_time), i64::from(tip.time));
        assert_ne!(right, tip.bits, "the boundary moves the difficulty");
        assert_eq!(f.accept(&[mine(&[0x99; 32], t, right, 2)], now), Err(Refusal::UnknownParent));
        let a = mine(&tip.hash, t, right, 2);
        assert_eq!(f.accept(&[a, mine(&[0x98; 32], t + 600, right, 2)], now), Err(Refusal::Unlinked));
        let old_version = (0u32..).map(|n| header(&tip.hash, t, tip.bits, 2, 3, n)).find(|h| pow_ok_under(h, EASY.pow_limit_bits)).expect("mined");
        assert_eq!(f.accept(&[old_version], now), Err(Refusal::Version));
        // keeping the old difficulty across the boundary is refused
        assert_eq!(f.accept(&[mine(&tip.hash, t, tip.bits, 2)], now), Err(Refusal::WrongDifficulty));
        let unmined = (0u32..).map(|n| header(&tip.hash, t, right, 2, 4, n)).find(|h| !pow_ok_under(h, EASY.pow_limit_bits)).expect("a miss");
        assert_eq!(f.accept(&[unmined], now), Err(Refusal::ProofOfWork));
        let median = { let mut v = f.last11(f.ring.len() - 1); v.sort_unstable(); v[5] };
        assert_eq!(f.accept(&[mine(&tip.hash, median, right, 2)], now), Err(Refusal::TimeTooOld));
        assert_eq!(f.accept(&[mine(&tip.hash, (now + MAX_FUTURE_SECS + 1) as u32, right, 2)], now), Err(Refusal::TimeTooNew));
        assert_eq!(f.tip(), tip, "no refused batch moved the tip");
        // off a boundary, a changed difficulty is refused too
        f.accept(&[mine(&tip.hash, t, right, 2)], now).expect("the boundary header with the right difficulty");
        let tip = f.tip();
        assert_eq!(f.accept(&[mine(&tip.hash, tip.time + 600, EASY.pow_limit_bits, 2)], now), Err(Refusal::WrongDifficulty));
    }

    /// ⭐⭐⭐ §22 6 — MOST WORK WINS: a branch from below the tip with more work replaces the chain (its old headers lose
    /// their confirmations); a branch with less or equal work stays out.
    #[test]
    fn the_header_follower_takes_the_most_work_branch() {
        let now = u64::from(T0) + 1_000_000;
        let mut f = follower();
        let main = chain(f.tip(), 12, 1);
        f.accept(&main, now).expect("main");
        let fork = f.ring[f.ring.len() - 4]; // height 9: three headers above it
        let short = chain(fork, 3, 2);
        assert_eq!(f.accept(&short, now), Ok(false), "equal work: the first-seen chain stays");
        assert_eq!(f.tip().hash, header_hash(&main[11]));
        let long = chain(fork, 4, 3);
        assert_eq!(f.accept(&long, now), Ok(true), "more work: the branch becomes the chain");
        assert_eq!(f.tip().hash, header_hash(&long[3]));
        assert_eq!(f.tip().height, 13);
        assert_eq!(f.confirmations(&header_hash(&main[11])), None, "a replaced header has no confirmations");
        assert_eq!(f.confirmations(&header_hash(&main[8])), Some(5), "the shared header keeps them");
    }

    /// ⭐ NO GROWTH: after 400 headers the follower holds RING entries and ten earlier timestamps, still follows, and refuses a
    /// header whose parent left the ring.
    #[test]
    fn the_header_follower_holds_constant_state() {
        let now = u64::from(T0) + 10_000_000;
        let mut f = follower();
        let hs = chain(f.tip(), 400, 1);
        for part in hs.chunks(50) {
            assert_eq!(f.accept(part, now), Ok(true));
        }
        assert_eq!(f.ring.len(), RING);
        assert!(f.before.len() <= 10);
        assert_eq!(f.tip().height, 400);
        let gone = f.ring[0].height - 1;
        let stale_parent = header_hash(&hs[gone as usize - 1]);
        assert_eq!(f.accept(&[mine(&stale_parent, T0 + 600 * (gone + 1), f.ring[0].bits, 9)], now), Err(Refusal::UnknownParent));
    }

    /// ⭐⭐⭐ §22 6 — TESTNET4'S RULES, as Bitcoin Core applies them: off a boundary a block more than two spacings after its
    /// parent may carry the proof-of-work limit — never sooner, never at a boundary; BIP 94 retargets from the period's FIRST
    /// difficulty, so a min-difficulty last block cannot drag the next period down; and a period's first block more than ten
    /// minutes before its parent is refused (the timewarp fix) even where median time would admit it.
    #[test]
    fn the_follower_takes_testnet4s_min_difficulty_and_bip94_rules() {
        let p = Params { allow_min_difficulty: true, bip94: true, ..EASY };
        let now = u64::from(T0) + 10_000_000;
        let times: [u32; 11] = std::array::from_fn(|i| T0 - 1000 * (10 - i as u32));
        let mut f = HeaderFollower::new(p, Checkpoint { hash: [0x22; 32], height: 0, bits: p.pow_limit_bits, period_first_time: T0, period_bits: p.pow_limit_bits, times });
        let main = chain(f.tip(), 24, 1);
        f.accept(&main, now).expect("three periods a little faster than the target: each raises the difficulty");
        let tip = f.tip();
        assert_ne!(tip.period_bits, p.pow_limit_bits, "PRECONDITION: the boundary raised the difficulty");
        // height 25: three spacings late, the limit is admitted; a moment later than one spacing, it is not
        let late = mine(&tip.hash, tip.time + 3, p.pow_limit_bits, 4);
        let early = mine(&tip.hash, tip.time + 1, p.pow_limit_bits, 5);
        assert_eq!(f.accept(&[early], now), Err(Refusal::WrongDifficulty), "⛔ a prompt block took the limit");
        assert_eq!(f.accept(&[late], now), Ok(true), "a late block may carry the limit");
        assert_eq!(f.tip().period_bits, tip.period_bits, "an exception is not the period's difficulty");
        // walk to the last block of the period, ending on a min-difficulty block
        let mut prev = f.tip();
        for _ in 0..p.interval {
            if (prev.height + 1) % p.interval == 0 {
                break; // the next header opens the next period
            }
            let late = prev.height + 2 == 32;
            let (t, b) = if late { (prev.time + 3, p.pow_limit_bits) } else { (prev.time + 1, prev.period_bits) };
            f.accept(&[mine(&prev.hash, t, b, 6)], now).expect("within the period");
            prev = f.tip();
        }
        assert_eq!(prev.bits, p.pow_limit_bits, "PRECONDITION: the period ends on a min-difficulty block");
        let from_period = next_bits_under(&p, prev.period_bits, i64::from(prev.period_first_time), i64::from(prev.time));
        let from_last = next_bits_under(&p, prev.bits, i64::from(prev.period_first_time), i64::from(prev.time));
        assert_ne!(from_period, from_last, "PRECONDITION: the two bases differ");
        assert_eq!(f.accept(&[mine(&prev.hash, prev.time + 1, from_last, 7)], now), Err(Refusal::WrongDifficulty), "⛔ BIP 94: dragged");
        // the timewarp: inside median time, yet more than ten minutes before its parent
        let mut g = HeaderFollower::new(p, Checkpoint { hash: [0x33; 32], height: 7, bits: p.pow_limit_bits, period_first_time: T0, period_bits: p.pow_limit_bits, times });
        let parent = g.tip();
        let want = next_bits_under(&p, parent.period_bits, i64::from(parent.period_first_time), i64::from(parent.time));
        let warp = mine(&parent.hash, parent.time - MAX_TIMEWARP_SECS - 1, want, 8);
        assert_eq!(g.accept(&[warp], now), Err(Refusal::TimeTooOld), "⛔ BIP 94: the timewarp passed");
        assert_eq!(g.accept(&[mine(&parent.hash, parent.time - MAX_TIMEWARP_SECS, want, 9)], now), Ok(true), "ten minutes is allowed");
        assert_eq!(f.accept(&[mine(&prev.hash, prev.time + 1, from_period, 10)], now), Ok(true), "the period's own base retargets");
    }

    /// ⭐⭐⭐ §22 6 — THREE FILTER PEERS MUST AGREE: fewer distinct peers wait; one peer repeating itself is one peer; any
    /// second value is a conflict that no majority settles.
    #[test]
    fn three_filter_peers_must_agree() {
        let (p, q, r, s) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        let (good, bad) = ([0xAA; 32], [0xBB; 32]);
        assert_eq!(agree(&[]), Agreement::Wait);
        assert_eq!(agree(&[(p, good), (q, good)]), Agreement::Wait, "two peers are not enough");
        assert_eq!(agree(&[(p, good), (p, good), (p, good)]), Agreement::Wait, "one peer three times is one peer");
        assert_eq!(agree(&[(p, good), (q, good), (r, good)]), Agreement::Agreed(good));
        assert_eq!(agree(&[(p, good), (q, good), (r, good), (s, bad)]), Agreement::Conflict, "a 3-to-1 majority settles nothing");
        assert_eq!(agree(&[(p, bad), (q, good), (r, good), (s, good)]), Agreement::Conflict);
    }

    /// ⭐ §22 6 — MONERO DAEMONS CROSS-CHECKED: the same rule over the block hash each daemon reports at a height.
    #[test]
    fn monero_daemons_cross_checked() {
        let d = |i: u8| [i; 32];
        let block = [0x5A; 32];
        assert_eq!(agree(&[(d(1), block), (d(2), block)]), Agreement::Wait, "one daemon plus one is not three");
        assert_eq!(agree(&[(d(1), block), (d(2), block), (d(3), block)]), Agreement::Agreed(block));
        assert_eq!(agree(&[(d(1), block), (d(2), block), (d(3), [0x5B; 32])]), Agreement::Conflict, "a lying daemon stops the count");
    }
}
