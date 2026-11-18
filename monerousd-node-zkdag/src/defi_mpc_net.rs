// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐ §BR-15 (spec §18.9) — THE CUSTODIAN'S OWN ENGINE: one custodian's half of the batch computation, holding ONLY its own
//! share of every value and talking to the others through a [`Comm`] (the node's onion links in production; in-memory channels
//! in the runtime's in-process run and its pins). Every custodian runs the same code in lockstep; nothing here ever holds a
//! second party's share, and each custodian deals its own randomness from its own entropy.
//!
//! The protocol, per primitive (honest majority `t = ⌊(n − 1)/3⌋`; every opened value is one the spec's closed list or a
//! masked opening allows):
//! - **deal**: every party evaluates its own random polynomials and sends party j its evaluation at j + 1 (GJKR/Pedersen
//!   dealing, borrowed); a dealt SUM over all dealers is uniform if one dealer is honest.
//! - **open** (degree t or 2t): every party sends its share to the king (party 0), the king interpolates and broadcasts.
//! - **multiply** (DN07, borrowed): a dealt double sharing `([r]_t, [r]_2t)`, open `xy + r` at degree 2t, subtract `[r]_t`.
//! - **random bits** (Damgård et al. 2006): open `a²` of a dealt random `a`, `b = (a/√a² + 1)/2`.
//! - **less-than, comparison, truncation, bit decomposition**: the carry-lookahead and Kogge–Stone shapes of `defi_clear`'s
//!   calibration engine, each party computing on its own share (Catrina–de Hoogh 2010, Catrina–Saxena 2010, DFKNT 2006).
//!
//! Cons, quantified: the king relays every opening (2(n − 1) elements per opened value, the DN07 cost); dealing double
//! sharings directly (each party deals each pair) costs 2n(n − 1) elements per product instead of DN07's extracted
//! 2n(n − 1)/(n − t) — ×1.33 at n = 4, offline, pipelined ahead of the batch.
//!
//! ROOT-LAYER: the custodian's own computation — the chain decides nothing here; `DefiSettleTx::verdict` decides the result.
//! MEASURED: `br15_the_custody_runtime_settles_a_batch_over_shares_and_every_node_accepts_it` runs every custodian on its own
//! thread over channels and the settlement passes the verdict.
//! MUST-STAY-GREEN: every `br15_*` pin of `defi_custody`, `defi_clear` and `defi_acceptance_tests`.
//! TWO-PARTY-REVIEWED: n parties, each its own thread and its own state, exchanging only the protocol's messages.

use crate::defi_clear::{candidate_scales, F255, K255, MASK255, TICK_RANGE};

/// A custodian's links to the others: send one message to party `to`, receive the next one from party `from`.
pub trait Comm {
    fn me(&self) -> usize;
    fn n(&self) -> usize;
    fn send(&mut self, to: usize, msg: Vec<F255>);
    /// `None` — the link is gone (the run aborts; the batch then expires and every order refunds).
    fn recv(&mut self, from: usize) -> Option<Vec<F255>>;
}

/// Why a run stopped.
pub type NetResult<T> = Result<T, &'static str>;

/// ⭐ In-memory links between `n` parties on one machine (the in-process run): one unbounded channel per ordered pair.
pub struct MemComm {
    me: usize,
    tx: Vec<std::sync::mpsc::Sender<Vec<F255>>>,
    rx: Vec<std::sync::mpsc::Receiver<Vec<F255>>>,
}

impl MemComm {
    /// The `n` parties' ends.
    #[must_use]
    pub fn mesh(n: usize) -> Vec<MemComm> {
        let mut txs: Vec<Vec<Option<std::sync::mpsc::Sender<Vec<F255>>>>> = (0..n).map(|_| (0..n).map(|_| None).collect()).collect();
        let mut rxs: Vec<Vec<Option<std::sync::mpsc::Receiver<Vec<F255>>>>> = (0..n).map(|_| (0..n).map(|_| None).collect()).collect();
        for from in 0..n {
            for to in 0..n {
                let (tx, rx) = std::sync::mpsc::channel();
                txs[from][to] = Some(tx);
                rxs[to][from] = Some(rx);
            }
        }
        txs.into_iter()
            .zip(rxs)
            .enumerate()
            .map(|(me, (tx, rx))| MemComm { me, tx: tx.into_iter().flatten().collect(), rx: rx.into_iter().flatten().collect() })
            .collect()
    }
}

impl Comm for MemComm {
    fn me(&self) -> usize {
        self.me
    }
    fn n(&self) -> usize {
        self.tx.len()
    }
    fn send(&mut self, to: usize, msg: Vec<F255>) {
        // a peer that has gone stops receiving; its own recv side reports it
        let _ = self.tx[to].send(msg);
    }
    fn recv(&mut self, from: usize) -> Option<Vec<F255>> {
        self.rx[from].recv().ok()
    }
}

/// ⭐ ONE CUSTODIAN'S ENGINE: its links, the threshold, its own randomness and the run's measured cost.
pub struct Party<C: Comm> {
    pub comm: C,
    pub t: usize,
    prg: blake3::OutputReader,
    pub online_rounds: u64,
    /// the network hops this party waited on (each exchange: one send to every party, one receive from every party) — the
    /// latency unit of a run over onion links
    pub hops: u64,
    pub sent_elements: u64,
    /// pre-dealt double sharings `(r_t, r_2t)` (DN07's preprocessing, borrowed): a multiplication set whose randomness is
    /// here takes ONE hop (its masked opening), not two
    doubles: std::collections::VecDeque<(F255, F255)>,
}

fn lagrange0(k: usize) -> Vec<F255> {
    (1..=k as u128)
        .map(|i| {
            (1..=k as u128).filter(|j| *j != i).fold(F255::ONE, |acc, j| acc.mul(F255::from_u128(j)).mul(F255::from_u128(j).sub(F255::from_u128(i)).inv()))
        })
        .collect()
}

impl<C: Comm> Party<C> {
    /// A custodian's engine keyed by 32 bytes of ITS OWN entropy.
    #[must_use]
    pub fn new(comm: C, key: &[u8; 32]) -> Self {
        let n = comm.n();
        Party { comm, t: (n - 1) / 3, prg: blake3::Hasher::new_keyed(key).update(b"USDMD-BR15-PARTY-PRG-v1").finalize_xof(), online_rounds: 0, hops: 0, sent_elements: 0, doubles: std::collections::VecDeque::new() }
    }
    fn n(&self) -> usize {
        self.comm.n()
    }
    fn me(&self) -> usize {
        self.comm.me()
    }
    /// 64 bits of this custodian's own randomness (its salts).
    pub fn draw_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.prg.fill(&mut b);
        u64::from_le_bytes(b)
    }
    /// A uniform field element of this custodian's own randomness (its masks).
    pub fn draw_field(&mut self) -> F255 {
        self.rand()
    }
    fn rand(&mut self) -> F255 {
        let mut b = [0u8; 32];
        self.prg.fill(&mut b);
        let l: [u64; 4] = core::array::from_fn(|k| u64::from_le_bytes(b[8 * k..8 * k + 8].try_into().unwrap_or([0; 8])));
        F255([l[0], l[1], l[2], l[3] >> 2]).add(F255::ZERO)
    }
    /// The evaluations at 1..=n of a random degree-`deg` polynomial with constant `v`.
    fn poly(&mut self, v: F255, deg: usize) -> Vec<F255> {
        let coeffs: Vec<F255> = std::iter::once(v).chain((0..deg).map(|_| self.rand())).collect();
        (1..=self.n() as u128).map(|x| coeffs.iter().rev().fold(F255::ZERO, |acc, c| acc.mul(F255::from_u128(x)).add(*c))).collect()
    }
    fn exchange(&mut self, out: Vec<Vec<F255>>, width: usize) -> NetResult<Vec<Vec<F255>>> {
        let n = self.n();
        self.hops += 1;
        for (j, m) in out.into_iter().enumerate() {
            self.sent_elements += m.len() as u64;
            self.comm.send(j, m);
        }
        (0..n)
            .map(|j| self.comm.recv(j).filter(|m| m.len() == width).ok_or("a custodian's link closed or sent a malformed message"))
            .collect()
    }
    /// ⭐ DEAL: every party deals one degree-`deg_k` sharing per item of `vals` (each party's own list, the same length and
    /// degrees everywhere); returns, per item, this party's share of the SUM over every dealer.
    pub fn deal_sum(&mut self, vals: &[(F255, usize)]) -> NetResult<Vec<F255>> {
        let n = self.n();
        let polys: Vec<Vec<F255>> = vals.iter().map(|(v, d)| self.poly(*v, *d)).collect();
        let out: Vec<Vec<F255>> = (0..n).map(|j| polys.iter().map(|p| p[j]).collect()).collect();
        let got = self.exchange(out, vals.len())?;
        Ok((0..vals.len()).map(|k| got.iter().fold(F255::ZERO, |a, m| a.add(m[k]))).collect())
    }
    /// `count` dealt sharings of degree `deg`: of 0 (`zero`) or of a uniformly random value.
    pub fn dealt(&mut self, count: usize, deg: usize, zero: bool) -> NetResult<Vec<F255>> {
        let vals: Vec<(F255, usize)> = (0..count).map(|_| (if zero { F255::ZERO } else { self.rand() }, deg)).collect();
        self.deal_sum(&vals)
    }
    /// Every party's message to all, collected (a broadcast round).
    pub fn broadcast(&mut self, msg: Vec<F255>) -> NetResult<Vec<Vec<F255>>> {
        let w = msg.len();
        let n = self.n();
        self.exchange(vec![msg; n], w)
    }
    /// ⭐ OPEN shared values of degree `deg` in ONE network hop: every party sends its shares to every other and each
    /// reconstructs from the first `deg + 1` (the same points everywhere, so every party opens the same values). The king
    /// relay this replaces took two hops per opening (to the king, back from it); a hop over onion links is the latency
    /// unit, so every opening's wall time halves (MEASURED by `hops`) for n − 1 × the king's bandwidth per opening.
    pub fn open_many(&mut self, mine: &[F255], deg: usize) -> NetResult<Vec<F255>> {
        self.online_rounds += 1;
        let all = self.broadcast(mine.to_vec())?;
        let w = lagrange0(deg + 1);
        Ok((0..mine.len()).map(|k| w.iter().zip(&all).fold(F255::ZERO, |a, (wi, m)| a.add(wi.mul(m[k])))).collect())
    }
    /// ⭐ PRE-DEAL `k` double sharings in ONE hop (every party deals its own, the sums are the shared randomness), so the
    /// multiplication sets that follow each take one hop. A caller that knows how many products a protocol needs (the
    /// comparison and prefix trees below: data-independent counts) deals them all up front.
    pub fn ensure_doubles(&mut self, k: usize) -> NetResult<()> {
        if self.doubles.len() >= k {
            return Ok(());
        }
        let need = k - self.doubles.len();
        let t = self.t;
        let rs: Vec<F255> = (0..need).map(|_| self.rand()).collect();
        let vals: Vec<(F255, usize)> = rs.iter().map(|r| (*r, t)).chain(rs.iter().map(|r| (*r, 2 * t))).collect();
        let dealt = self.deal_sum(&vals)?;
        let (rt, r2t) = dealt.split_at(need);
        self.doubles.extend(rt.iter().copied().zip(r2t.iter().copied()));
        Ok(())
    }
    /// ⭐ DN07 MULTIPLY, every pair in one set: one hop when its double sharings are pre-dealt, two otherwise.
    pub fn mul_many(&mut self, a: &[F255], b: &[F255]) -> NetResult<Vec<F255>> {
        self.ensure_doubles(a.len())?;
        let pairs: Vec<(F255, F255)> = (0..a.len()).filter_map(|_| self.doubles.pop_front()).collect();
        let masked: Vec<F255> = a.iter().zip(b).zip(&pairs).map(|((x, y), (_, m))| x.mul(*y).add(*m)).collect();
        let opened = self.open_many(&masked, 2 * self.t)?;
        Ok(opened.iter().zip(&pairs).map(|(o, (r, _))| o.sub(*r)).collect())
    }
    /// `count` shared random BITS in TWO hops (Damgård–Fitzi–Kiltz–Nielsen–Toft 2006, borrowed): deal a random `r` with a
    /// degree-2t sharing of 0 beside it, open `r² + 0` from the local products (re-randomized: the bare product shares would
    /// reveal `r` up to sign), and `b = (r/√(r²) + 1)/2`. A zero square is redrawn (every party sees the same opening).
    pub fn random_bits(&mut self, count: usize) -> NetResult<Vec<F255>> {
        let half = F255::from_u128(2).inv();
        let mut out = Vec::with_capacity(count);
        while out.len() < count {
            let need = count - out.len();
            let t = self.t;
            let vals: Vec<(F255, usize)> = (0..need).map(|_| (self.rand(), t)).chain((0..need).map(|_| (F255::ZERO, 2 * t))).collect();
            let dealt = self.deal_sum(&vals)?;
            let (r, z) = dealt.split_at(need);
            let sq: Vec<F255> = r.iter().zip(z).map(|(ri, zi)| ri.mul(*ri).add(*zi)).collect();
            let opened = self.open_many(&sq, 2 * t)?;
            for (ri, a2) in r.iter().zip(opened) {
                let Some(root) = (a2 != F255::ZERO).then(|| a2.sqrt()).flatten() else { continue };
                out.push(ri.mul(root.inv().mul(half)).add(half));
            }
        }
        Ok(out)
    }
    /// Shared random values below `2^w` with their bits, one per width — ALL drawn in one `random_bits` (two hops), never one
    /// draw per value.
    fn below_pow2_many(&mut self, widths: &[u32]) -> NetResult<Vec<(F255, Vec<F255>)>> {
        let total: usize = widths.iter().map(|w| *w as usize).sum();
        let all = self.random_bits(total)?;
        let mut at = 0usize;
        Ok(widths
            .iter()
            .map(|w| {
                let bs = all[at..at + *w as usize].to_vec();
                at += *w as usize;
                let v = bs.iter().enumerate().fold(F255::ZERO, |acc, (i, b)| acc.add(b.mul(F255::pow2(i as u32))));
                (v, bs)
            })
            .collect())
    }
    /// `[c < r]` for many public `c` and shared bit vectors of `r` (the carry-lookahead tree).
    pub fn public_lt_many(&mut self, cs: &[F255], r_bits: &[Vec<F255>]) -> NetResult<Vec<F255>> {
        // the tree's products, counted from the bit lengths alone, pre-dealt in one hop: each level is then one hop
        let mut need = 0usize;
        for bits in r_bits {
            let mut len = bits.len();
            while len > 1 {
                need += 2 * (len / 2);
                len = len.div_ceil(2);
            }
        }
        self.ensure_doubles(need)?;
        let mut level: Vec<Vec<(F255, F255)>> = cs
            .iter()
            .zip(r_bits)
            .map(|(c, bits)| bits.iter().enumerate().map(|(i, rb)| if c.bit(i as u32) { (F255::ZERO, *rb) } else { (*rb, F255::ONE.sub(*rb)) }).collect())
            .collect();
        while level.iter().any(|l| l.len() > 1) {
            let (mut a, mut b) = (Vec::new(), Vec::new());
            for l in &level {
                for ch in l.chunks(2) {
                    if let [lo, hi] = ch {
                        a.push(hi.1);
                        b.push(lo.0);
                        a.push(hi.1);
                        b.push(lo.1);
                    }
                }
            }
            let prods = self.mul_many(&a, &b)?;
            let mut k = 0usize;
            level = level
                .into_iter()
                .map(|l| {
                    l.chunks(2)
                        .map(|ch| {
                            if let [_, hi] = ch {
                                let out = (hi.0.add(prods[k]), prods[k + 1]);
                                k += 2;
                                out
                            } else {
                                ch[0]
                            }
                        })
                        .collect()
                })
                .collect();
        }
        Ok(level.into_iter().map(|l| l[0].0).collect())
    }
    /// ⭐ EXACT TRUNCATION `⌊v / 2^k⌋` for each `(v, k, bound)` (`v < 2^bound`, `bound + MASK255 < 255`; `k ≥ bound` gives 0).
    pub fn trunc_many(&mut self, vs: &[(F255, u32, u32)]) -> NetResult<Vec<F255>> {
        let live: Vec<usize> = (0..vs.len()).filter(|i| vs[*i].1 < vs[*i].2).collect();
        let (mut masked, mut lo_bits, mut r_los) = (Vec::new(), Vec::new(), Vec::new());
        let widths: Vec<u32> = live.iter().flat_map(|i| [vs[*i].1, vs[*i].2 - vs[*i].1 + MASK255]).collect();
        let mut draws = self.below_pow2_many(&widths)?.into_iter();
        for i in &live {
            let (v, k, _) = vs[*i];
            let ((r_lo, bits), (r_hi, _)) = (draws.next().ok_or("a mask was not drawn")?, draws.next().ok_or("a mask was not drawn")?);
            masked.push(v.add(r_lo).add(r_hi.mul(F255::pow2(k))));
            lo_bits.push(bits);
            r_los.push(r_lo);
        }
        let mut out = vec![F255::ZERO; vs.len()];
        if live.is_empty() {
            return Ok(out);
        }
        let opened = self.open_many(&masked, self.t)?;
        let c_lo: Vec<F255> = opened.iter().zip(&live).map(|(c, i)| c.mod_pow2(vs[*i].1)).collect();
        let borrow = self.public_lt_many(&c_lo, &lo_bits)?;
        for (j, i) in live.iter().enumerate() {
            let (v, k, _) = vs[*i];
            let v_mod = c_lo[j].sub(r_los[j]).add(borrow[j].mul(F255::pow2(k)));
            out[*i] = v.sub(v_mod).mul(F255::pow2(k).inv());
        }
        Ok(out)
    }
    /// ⭐ `[a ≥ b]` for many shared pairs (`|a − b| < 2^(K255 − 1)`): the lifted difference's bit `K255 − 1`.
    pub fn geq_many(&mut self, ab: &[(F255, F255)]) -> NetResult<Vec<F255>> {
        let l = K255 - 1;
        let zs: Vec<(F255, u32, u32)> = ab.iter().map(|(a, b)| (a.sub(*b).add(F255::pow2(l)), l, K255)).collect();
        self.trunc_many(&zs)
    }
    /// ⭐ BIT DECOMPOSITION: the `l` shared bits of each `v < 2^l` (masked opening + Kogge–Stone borrow prefix).
    pub fn bits_many(&mut self, vs: &[F255], l: u32) -> NetResult<Vec<Vec<F255>>> {
        let (mut masked, mut r_bits) = (Vec::new(), Vec::new());
        let widths: Vec<u32> = vs.iter().flat_map(|_| [l, MASK255]).collect();
        let mut draws = self.below_pow2_many(&widths)?.into_iter();
        for v in vs {
            let ((r_lo, bits), (r_hi, _)) = (draws.next().ok_or("a mask was not drawn")?, draws.next().ok_or("a mask was not drawn")?);
            masked.push(v.add(r_lo).add(r_hi.mul(F255::pow2(l))));
            r_bits.push(bits);
        }
        let opened = self.open_many(&masked, self.t)?;
        let cs: Vec<F255> = opened.iter().map(|c| c.mod_pow2(l)).collect();
        let mut gp: Vec<Vec<(F255, F255)>> = cs
            .iter()
            .zip(&r_bits)
            .map(|(c, bits)| bits.iter().enumerate().map(|(i, rb)| if c.bit(i as u32) { (F255::ZERO, *rb) } else { (*rb, F255::ONE.sub(*rb)) }).collect())
            .collect();
        // the prefix tree's and the final row's products, counted from the widths alone, pre-dealt in one hop
        let mut need = 0usize;
        let mut dd = 1usize;
        while dd < l as usize {
            need += gp.iter().map(|row| 2 * row.len().saturating_sub(dd)).sum::<usize>();
            dd *= 2;
        }
        need += r_bits.iter().map(|b| b.len().saturating_sub(1)).sum::<usize>();
        self.ensure_doubles(need)?;
        let mut d = 1usize;
        while d < l as usize {
            let (mut a, mut b) = (Vec::new(), Vec::new());
            for row in &gp {
                for i in d..row.len() {
                    a.push(row[i].1);
                    b.push(row[i - d].0);
                    a.push(row[i].1);
                    b.push(row[i - d].1);
                }
            }
            let prods = self.mul_many(&a, &b)?;
            let mut k = 0usize;
            for row in &mut gp {
                let prev = row.clone();
                for i in d..row.len() {
                    row[i] = (prev[i].0.add(prods[k]), prods[k + 1]);
                    k += 2;
                }
            }
            d *= 2;
        }
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for (row, bits) in gp.iter().zip(&r_bits) {
            for i in 1..bits.len() {
                a.push(bits[i]);
                b.push(row[i - 1].0);
            }
        }
        let prods = self.mul_many(&a, &b)?;
        let two = F255::from_u128(2);
        let mut k = 0usize;
        Ok(cs
            .iter()
            .zip(&r_bits)
            .zip(&gp)
            .map(|((c, bits), row)| {
                (0..bits.len())
                    .map(|i| {
                        let x = if i == 0 {
                            bits[0]
                        } else {
                            let p = prods[k];
                            k += 1;
                            bits[i].add(row[i - 1].0).sub(two.mul(p))
                        };
                        if c.bit(i as u32) { F255::ONE.sub(x) } else { x }
                    })
                    .collect()
            })
            .collect())
    }
    /// ⭐ THE STAGED TICK SEARCH over this party's shares of `ΣX` and of `ΣY` AS A FUNCTION OF THE CANDIDATE (`sy_at(t)`: the
    /// pool's Y plus the Y lines of the buckets that FILL at `t` — spec §18.10, finding A-F46, `defi_custody::clear_tick`; a
    /// linear, public selection of shares, so no comparison per order) — `defi_clear::tick_search`'s shape. The test
    /// `ΣY(t)·D_t ≥ ΣX·N_t` stays monotone (ΣY(t) never grows with t, the price does), so the staged search has one answer.
    pub fn tick_search(&mut self, sx: F255, sy_at: &dyn Fn(i64) -> F255, around: i64, width: usize) -> NetResult<i64> {
        let (mut lo, mut hi) = (-TICK_RANGE, TICK_RANGE);
        let half = (width / 2) as i64;
        let mut cands: Vec<i64> = ((around - half).max(lo + 1)..(around + half + 1).min(hi)).collect();
        while hi - lo > 1 {
            let pairs: Vec<(F255, F255)> = cands.iter().map(|t| { let (ys, xs) = candidate_scales(*t); (sy_at(*t).mul(ys), sx.mul(xs)) }).collect();
            let ge = self.geq_many(&pairs)?;
            let bits = self.open_many(&ge, self.t)?;
            for (t, b) in cands.iter().zip(&bits) {
                if *b == F255::ONE {
                    lo = lo.max(*t);
                } else {
                    hi = hi.min(*t);
                }
            }
            let step = ((hi - lo) / (width as i64 + 1)).max(1);
            cands = (1..=width as i64).map(|k| lo + k * step).filter(|c| *c < hi).collect();
        }
        Ok(lo)
    }
}

/// `⌈2^k / m⌉` as a field element (long division; `m < 2^24`).
#[must_use]
pub fn ceil_pow2_over(k: u32, m: u128) -> F255 {
    let (mut q, mut rem) = (F255::ZERO, 0u128);
    for bit in std::iter::once(1u128).chain(std::iter::repeat(0).take(k as usize)) {
        rem = 2 * rem + bit;
        q = q.add(q);
        if rem >= m {
            rem -= m;
            q = q.add(F255::ONE);
        }
    }
    if rem == 0 { q } else { q.add(F255::ONE) }
}
