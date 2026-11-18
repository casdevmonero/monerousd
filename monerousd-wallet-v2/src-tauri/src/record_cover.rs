// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ DB-223 Q2 §12f — the RECORD-FETCH COVER SET, for refutation: candidate shapes MEASURED before one is chosen.
//!
//! A note with no captured path fetches its record (`/da_record {ordinal}`) and asks its own index shard by NAME, so
//! both asks ride one set of `COVER_SET` ordinals per note. Three constraints collide (spec §12f):
//! - (R) reproducible — two restores of one note name the identical set;
//! - (A) age-matched — the real record is not separable by age (the Monero 2018 lesson: real = youngest);
//! - (T) no time leak — decoys placed around `o` reveal it by geometry (lane-db224-carriage's review, 05:40).
//!
//! Nothing here is on the wire: these are the candidate samplers and the measuring pin.

/// Members of one note's set (the real record plus decoys): the OLI wave's own `WAVE_SHARDS`, the already-named 1-of-16
/// k-anonymity class.
pub const COVER_SET: usize = usdmd_node::oli::WAVE_SHARDS;

/// The largest offset scale a log-uniform OFFSET decoy takes, as a power of two (the refuted two-sided shape).
pub const LOG_SPAN_BITS: u32 = 40;

/// A keyed stream: the `i`-th 64-bit draw under the wallet's cover key `k` for context `ctx`.
fn draw(k: &[u8; 32], ctx: &[u64], i: u64) -> u64 {
    use usdmd_node::fixed::FixedBytes;
    let mut h = blake3::Hasher::new_keyed(k);
    h.update(b"MUSD/q2/record-cover/v1");
    for c in ctx {
        h.update(&c.to_le_bytes());
    }
    h.update(&i.to_le_bytes());
    u64::from_le_bytes(h.finalize().as_bytes()[..8].fixed())
}

/// A uniform real in `[0, 1)` from a 64-bit draw.
fn unit(x: u64) -> f64 {
    (x >> 11) as f64 / (1u64 << 53) as f64
}

/// A log-uniform magnitude in `[1, 2^bits)`.
fn log_uniform_bits(x: u64, bits: u32) -> u64 {
    (2f64.powf(unit(x) * f64::from(bits))).floor().max(1.0) as u64
}

/// The epoch tip `N_e = 2^⌊log2 n⌋`: stable until the chain doubles (lane-db224-carriage's §12f middle ground).
#[must_use]
pub fn epoch_tip(n: u64) -> u64 {
    1u64 << (63 - n.max(1).leading_zeros())
}

/// Candidate (1), the CALIBRATION: uniform decoys over `[1, n]` — a function of the tip, so not even reproducible.
pub fn uniform(k: &[u8; 32], o: u64, n: u64) -> Vec<i128> {
    (0..(COVER_SET as u64 - 1)).map(|i| i128::from(1 + draw(k, &[1, o], i) % n)).collect()
}

/// Candidate (2), REFUTED (geometry): decoys `o ± δ`, sign keyed, `|δ|` log-uniform — the set is log-symmetric around `o`.
pub fn two_sided_offsets(k: &[u8; 32], o: u64) -> Vec<i128> {
    (0..(COVER_SET as u64 - 1))
        .map(|i| {
            let x = draw(k, &[2, o], i);
            let d = i128::from(log_uniform_bits(x, LOG_SPAN_BITS));
            if x & 1 == 1 { i128::from(o) + d } else { i128::from(o) - d }
        })
        .collect()
}

/// Candidate (3): EPOCH-KEYED AGE-MATCHED — decoy ages drawn INDEPENDENTLY of `o`'s position from the recency law
/// (log-uniform in `[1, N_e)`), placed relative to the epoch tip `N_e` of the tip `n`, keyed by `(k, o, e)`: identical
/// for every restore inside one epoch; two restores in different epochs intersect (the named residual).
pub fn epoch_age_matched(k: &[u8; 32], o: u64, n: u64) -> Vec<i128> {
    let ne = epoch_tip(n);
    let e = u64::from(ne.trailing_zeros());
    (0..(COVER_SET as u64 - 1))
        .map(|i| i128::from(ne) - i128::from(log_uniform_bits(draw(k, &[3, o, e], i), ne.trailing_zeros()).min(ne - 1)))
        .collect()
}

/// Candidate (4): PAST-ONLY log-uniform around a KEYED anchor `A = f(k, o, e)` drawn uniformly in `[1, N_e]` — the set's
/// centre is not `o`; the real record is placed among decoys hung below `A`.
pub fn keyed_anchor_past_only(k: &[u8; 32], o: u64, n: u64) -> Vec<i128> {
    let ne = epoch_tip(n);
    let e = u64::from(ne.trailing_zeros());
    let anchor = 1 + draw(k, &[4, o, e], u64::MAX) % ne;
    (0..(COVER_SET as u64 - 1))
        .map(|i| i128::from(anchor) - i128::from(log_uniform_bits(draw(k, &[4, o, e], i), ne.trailing_zeros())) + 1)
        .collect()
}

/// The stream's reach in records: a note younger than this is captured from the public path-refresh stream and never
/// fetched, so a cover set serves only ages `≥ STREAM_REACH` (the node's `merge_depth_cap`).
pub const STREAM_REACH: u64 = 3_600;

/// Candidate (i), the node lane's middle ground (§12f review 05:50): TIP-RELATIVE AGE-MATCHED over ages `≥ STREAM_REACH`,
/// quantized to a tip quantum `q`: decoy ages log-uniform in `[STREAM_REACH, N_q)` from `N_q = ⌊n / q⌋·q`, keyed by
/// `(k, o, N_q)` — one set for every restore inside one quantum; restores in different quanta differ (the named
/// cross-restore residual, measured below).
pub fn quantized_age_matched(k: &[u8; 32], o: u64, n: u64, q: u64) -> Vec<i128> {
    let nq = (n / q.max(1)) * q.max(1);
    let span = nq.saturating_sub(STREAM_REACH).max(2);
    let bits = 64 - span.leading_zeros();
    (0..(COVER_SET as u64 - 1))
        .map(|i| {
            let age = STREAM_REACH + log_uniform_bits(draw(k, &[5, o, nq], i), bits).min(span - 1);
            i128::from(nq) - i128::from(age)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic xorshift stream for the trial draws (the wallets' keys and their notes' ordinals).
    fn rng(seed: u64) -> impl FnMut() -> u64 {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        }
    }

    /// The members an observer sees as REAL candidates: the set as asked, minus every member that answers empty (it
    /// does not exist at tip `n`) — the real record always exists.
    fn existing(real: u64, decoys: &[i128], n: u64) -> Vec<i128> {
        let mut m: Vec<i128> = decoys.iter().copied().filter(|d| *d >= 1 && *d <= i128::from(n)).collect();
        m.push(i128::from(real));
        m
    }

    /// Observer (a), §12b: names the YOUNGEST existing member.
    fn youngest(set: &[i128]) -> i128 {
        *set.iter().max().expect("the real member exists")
    }

    /// Observer (b), the node lane's CENTRED-LIKELIHOOD observer: scores each member `c` by how well the others fit
    /// `c ± log-uniform` (density ∝ 1/|δ|) and names the argmax — it finds any set hung around its real member.
    fn centred(set: &[i128]) -> i128 {
        *set.iter()
            .max_by(|a, b| {
                let score = |c: i128| -> f64 {
                    set.iter().filter(|m| **m != c).map(|m| -(((*m - c).abs().max(1)) as f64).ln()).sum()
                };
                score(**a).partial_cmp(&score(**b)).expect("finite scores")
            })
            .expect("the real member exists")
    }

    /// ⭐ DB-223 Q2 §12f — THE MEASUREMENT. 8,000 restores of a recency-skewed real note (age log-uniform in `[1, n)`,
    /// `n = 1.5 · 2^24` records, mid-epoch) against BOTH observers, for the four shapes, plus the EFFECTIVE set size (how
    /// many members exist). It PRINTS every rate beside the 1/16 floor — the numbers decide the spec — and ASSERTS only
    /// what is settled:
    /// - CALIBRATION: uniform decoys single out a recency-skewed real record (observer a) far above 1/16;
    /// - the refuted two-sided shape IS found by the centred observer (b) far above 1/16 (its geometry leak, armed);
    /// - (R): the keyed shapes are identical at two tips inside one epoch; the calibration moves with the tip.
    /// Non-proving and pure (no wire, no PIR).
    #[test]
    fn q2_12f_two_observers_measured_against_four_cover_shapes() {
        let n: u64 = 3 << 23; // 1.5 · 2^24: mid-epoch, the young-note case at its sharpest
        let trials = 8_000u32;
        let mut r = rng(0x12F);
        type Shape = fn(&[u8; 32], u64, u64) -> Vec<i128>;
        let shapes: [(&str, Shape); 4] = [
            ("uniform", uniform),
            ("two-sided offsets", |k, o, _n| two_sided_offsets(k, o)),
            ("epoch age-matched", epoch_age_matched),
            ("keyed-anchor past-only", keyed_anchor_past_only),
        ];
        let mut hits = [[0u32; 2]; 4];
        let mut exist_sum = [0u64; 4];
        for _ in 0..trials {
            let mut k = [0u8; 32];
            for c in k.chunks_mut(8) {
                c.copy_from_slice(&r().to_le_bytes());
            }
            let age = log_uniform_bits(r(), 64 - n.leading_zeros()).clamp(1, n - 1);
            let o = n - age;
            for (s, (_, shape)) in shapes.iter().enumerate() {
                let set = existing(o, &shape(&k, o, n), n);
                exist_sum[s] += set.len() as u64;
                hits[s][0] += u32::from(youngest(&set) == i128::from(o));
                hits[s][1] += u32::from(centred(&set) == i128::from(o));
            }
        }
        let rate = |h: u32| f64::from(h) / f64::from(trials);
        for (s, (name, _)) in shapes.iter().enumerate() {
            eprintln!(
                "[q2-§12f] {name:<24} youngest {:.3} · centred {:.3} · effective set {:.1} of {COVER_SET} (floor 1/{COVER_SET} = {:.3})",
                rate(hits[s][0]),
                rate(hits[s][1]),
                exist_sum[s] as f64 / f64::from(trials),
                1.0 / COVER_SET as f64,
            );
        }
        let floor = 1.0 / COVER_SET as f64;
        assert!(rate(hits[0][0]) > 4.0 * floor, "CALIBRATION: uniform decoys single out a recency-skewed real record");
        assert!(rate(hits[1][1]) > 4.0 * floor, "CALIBRATION: the centred observer finds a set hung around o");
        // (R) inside one epoch: two tips, one set; the calibration moves with the tip.
        let k = [0x5Au8; 32];
        let o = 1_000_000u64;
        let (n1, n2) = (3u64 << 23, (3u64 << 23) + 777_777);
        assert_eq!(epoch_tip(n1), epoch_tip(n2), "PRECONDITION: one epoch");
        assert_eq!(epoch_age_matched(&k, o, n1), epoch_age_matched(&k, o, n2), "(R) epoch-keyed: one set in one epoch");
        assert_eq!(keyed_anchor_past_only(&k, o, n1), keyed_anchor_past_only(&k, o, n2), "(R) keyed anchor: one set");
        assert_ne!(uniform(&k, o, n1), uniform(&k, o, n2), "CALIBRATION: uniform moves with the tip");
    }

    /// ⭐ DB-223 Q2 §12f — CHOOSING q BY MEASUREMENT (the node lane's condition, 05:50). For candidate (i) at
    /// q ∈ {SHARD_BLOCKS, 8×, 64×, 512×, N_e}: the youngest and centred observers' rates over 6,000 restores of a note
    /// that NEEDS the fetch (age log-uniform in `[STREAM_REACH, n)`), each restored at a tip drawn uniformly inside its
    /// quantum; and the probability that two restores of one note name the SAME set (no intersection) for restore gaps of
    /// 1 day, 1 week and 1 month at the 2 blocks/s target. It PRINTS the table — the largest q whose youngest rate stays
    /// near 1/16 is the choice — and ASSERTS only (R) inside a quantum and that the observers' rates are well defined.
    /// Non-proving and pure.
    #[test]
    fn q2_12f_the_quantum_q_measured_youngest_centred_and_two_restore_intersection() {
        let n_base: u64 = 1 << 26;
        let shard = usdmd_node::window_index::SHARD_BLOCKS;
        // q = 1 is the fully tip-relative end (matched, never reproducible): the (A) calibration of the trade.
        let qs = [1, shard, shard * 8, shard * 64, shard * 512, epoch_tip(n_base)];
        let trials = 6_000u32;
        let per_day = 2 * 86_400u64; // records per day at the 2 blocks/s target
        for q in qs {
            let mut r = rng(0x9_12F ^ q);
            let (mut hy, mut hc) = (0u32, 0u32);
            for _ in 0..trials {
                let mut k = [0u8; 32];
                for c in k.chunks_mut(8) {
                    c.copy_from_slice(&r().to_le_bytes());
                }
                let n = n_base + r() % q; // a restore anywhere inside the quantum
                let span_bits = 64 - (n - STREAM_REACH).leading_zeros();
                let age = (STREAM_REACH - 1 + log_uniform_bits(r(), span_bits)).clamp(STREAM_REACH, n - 1);
                let o = n - age;
                let set = existing(o, &quantized_age_matched(&k, o, n, q), n);
                hy += u32::from(youngest(&set) == i128::from(o));
                hc += u32::from(centred(&set) == i128::from(o));
            }
            // Two restores of one note, `gap` records apart: the SAME set iff both tips fall in one quantum.
            let same = |gap: u64| -> f64 { if gap >= q { 0.0 } else { 1.0 - gap as f64 / q as f64 } };
            eprintln!(
                "[q2-§12f-q] q = {q:>10} ({:>7.2} days) · youngest {:.3} · centred {:.3} (floor {:.3}) · two restores name \
                 the SAME set: 1 day apart {:.2}, 1 week {:.2}, 1 month {:.2}",
                q as f64 / per_day as f64,
                f64::from(hy) / f64::from(trials),
                f64::from(hc) / f64::from(trials),
                1.0 / COVER_SET as f64,
                same(per_day),
                same(7 * per_day),
                same(30 * per_day),
            );
        }
        // (R) inside one quantum: two tips, one set.
        let (k, o, q) = ([0x33u8; 32], 5_000_000u64, shard * 64);
        let n1 = (n_base / q) * q;
        assert_eq!(quantized_age_matched(&k, o, n1, q), quantized_age_matched(&k, o, n1 + q - 1, q), "(R) one set per quantum");
        assert_ne!(quantized_age_matched(&k, o, n1, q), quantized_age_matched(&k, o, n1 + q, q), "a new quantum, a new set");
    }
}
