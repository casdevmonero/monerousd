// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! A two-server distributed point function, the write primitive of the anonymous-broadcast rounds (spec §6d).
//!
//! BORROWED: Boyle, Gilboa and Ishai, "Function Secret Sharing: Improvements and Extensions", CCS 2016, the tree construction;
//! Corrigan-Gibbs, Boneh and Mazières, "Riposte", S&P 2015, its use for anonymous writes.
//!
//! `gen(alpha, beta)` makes two keys. Each key alone is a seed and correction words that look uniformly random to anyone without
//! the other key, so one server learns nothing about where or what the client wrote. Evaluated at every slot and added (XOR), the
//! two keys give `beta` at slot `alpha` and zero everywhere else. A client with nothing to send writes an all-zero `beta`, and its
//! keys have the same size and the same distribution as a real write's.
//!
//! Post-quantum: the only primitive is a PRG, here blake3 in extendable-output mode. Security rests on blake3 being a PRG, which a
//! quantum computer weakens only by Grover's square root, so 32-byte seeds keep 128-bit security against it.
//!
//! VERIFIABLE (de Castro and Polychroniadou, "Lightweight, Maliciously Secure Verifiable Function Secret Sharing", Eurocrypt 2022):
//! each server hashes its full evaluation into one 32-byte proof (`eval_all_verified`). For an honest key pair the two proofs are
//! equal; for a pair that writes two slots or more, or two keys from different pairs, they differ but with probability about 2^-256.
//! The servers compare proofs and drop a client whose proofs differ, learning nothing else about its write.

/// Seed length in bytes. 32 bytes, so Grover's speed-up leaves 128-bit security.
pub const SEED: usize = 32;

/// One level's correction word: a seed and the two control-bit corrections.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Correction {
    seed: [u8; SEED],
    left: bool,
    right: bool,
}

/// One server's key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    party: bool,
    seed: [u8; SEED],
    levels: Vec<Correction>,
    /// The proof correction: the two leaf proofs at the written slot, added, so that slot's proofs agree too.
    check: [u8; PROOF],
    /// The output correction, as long as one slot.
    last: Vec<u8>,
}

/// A leaf proof's length. 64 bytes, so a collision costs about 2^256 hashing classically and 2^170 with a quantum computer.
pub const PROOF: usize = 64;

impl Key {
    /// The key's size on the wire, which is the same for every write of the same table shape.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        1 + SEED + self.levels.len() * (SEED + 1) + PROOF + self.last.len()
    }

    /// The bytes a client sends to its server.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        out.push(u8::from(self.party));
        out.extend_from_slice(&self.seed);
        for c in &self.levels {
            out.extend_from_slice(&c.seed);
            out.push(u8::from(c.left) | (u8::from(c.right) << 1));
        }
        out.extend_from_slice(&self.check);
        out.extend_from_slice(&self.last);
        out
    }

    /// Reads a key for a table of `2^depth` slots of `slot` bytes. `None` for any other length or a malformed byte, so a server
    /// never evaluates a key of the wrong shape.
    #[must_use]
    pub fn from_bytes(bytes: &[u8], depth: usize, slot: usize) -> Option<Key> {
        if bytes.len() != 1 + SEED + depth * (SEED + 1) + PROOF + slot || bytes[0] > 1 {
            return None;
        }
        let mut at = 1;
        let mut seed = [0u8; SEED];
        seed.copy_from_slice(&bytes[at..at + SEED]);
        at += SEED;
        let mut levels = Vec::with_capacity(depth);
        for _ in 0..depth {
            let mut s = [0u8; SEED];
            s.copy_from_slice(&bytes[at..at + SEED]);
            let flags = bytes[at + SEED];
            if flags > 3 {
                return None;
            }
            levels.push(Correction { seed: s, left: flags & 1 == 1, right: flags & 2 == 2 });
            at += SEED + 1;
        }
        let mut check = [0u8; PROOF];
        check.copy_from_slice(&bytes[at..at + PROOF]);
        at += PROOF;
        Some(Key { party: bytes[0] == 1, seed, levels, check, last: bytes[at..].to_vec() })
    }
}

/// A leaf's proof before correction: a hash of the slot and the leaf seed.
fn leaf_proof(x: u64, seed: &[u8; SEED]) -> [u8; PROOF] {
    let mut h = blake3::Hasher::new_derive_key("monerousd dpf leaf proof v1");
    h.update(&x.to_le_bytes());
    h.update(seed);
    let mut out = [0u8; PROOF];
    h.finalize_xof().fill(&mut out);
    out
}

/// Folds one leaf proof into the running proof: `pi ← pi ⊕ H(pi ⊕ leaf)`, so the result depends on every leaf in order.
fn fold_proof(pi: &mut [u8; PROOF], leaf: &[u8; PROOF]) {
    let mut x = *pi;
    xor_into(&mut x, leaf);
    let mut h = blake3::Hasher::new_derive_key("monerousd dpf proof fold v1");
    h.update(&x);
    let mut out = [0u8; PROOF];
    h.finalize_xof().fill(&mut out);
    xor_into(pi, &out);
}

/// The leaf seed and control bit one key reaches at slot `x`.
fn walk(key: &Key, x: u64) -> ([u8; SEED], bool) {
    let depth = key.levels.len();
    let mut s = key.seed;
    let mut t = key.party;
    for (i, c) in key.levels.iter().enumerate() {
        let (mut l, mut tl, mut r, mut tr) = expand(&s);
        if t {
            l = xor_seed(&l, &c.seed);
            r = xor_seed(&r, &c.seed);
            tl ^= c.left;
            tr ^= c.right;
        }
        if bit(x, i, depth) {
            s = r;
            t = tr;
        } else {
            s = l;
            t = tl;
        }
    }
    (s, t)
}

/// The PRG for one tree node: two child seeds and two control bits.
fn expand(seed: &[u8; SEED]) -> ([u8; SEED], bool, [u8; SEED], bool) {
    let mut h = blake3::Hasher::new_derive_key("monerousd dpf node v1");
    h.update(seed);
    let mut out = [0u8; 2 * SEED + 1];
    h.finalize_xof().fill(&mut out);
    let mut l = [0u8; SEED];
    let mut r = [0u8; SEED];
    l.copy_from_slice(&out[..SEED]);
    r.copy_from_slice(&out[SEED..2 * SEED]);
    (l, out[2 * SEED] & 1 == 1, r, out[2 * SEED] & 2 == 2)
}

/// A leaf seed stretched to one slot.
fn convert(seed: &[u8; SEED], slot: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key("monerousd dpf leaf v1");
    h.update(seed);
    let mut out = vec![0u8; slot];
    h.finalize_xof().fill(&mut out);
    out
}

fn xor_into(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

fn xor_seed(a: &[u8; SEED], b: &[u8; SEED]) -> [u8; SEED] {
    let mut out = *a;
    xor_into(&mut out, b);
    out
}

/// Bit `i` of `alpha`, most significant first, for a tree of `depth` levels.
fn bit(alpha: u64, i: usize, depth: usize) -> bool {
    (alpha >> (depth - 1 - i)) & 1 == 1
}

/// Two keys that write `beta` at slot `alpha` of a table of `2^depth` slots, each `beta.len()` bytes. `random` must be 64 bytes
/// from a cryptographic source: the two root seeds. `None` when `alpha` is outside the table or the depth is not 1 to 32.
#[must_use]
pub fn gen(alpha: u64, beta: &[u8], depth: usize, random: &[u8; 2 * SEED]) -> Option<(Key, Key)> {
    if depth == 0 || depth > 32 || alpha >> depth != 0 {
        return None;
    }
    let mut s0 = [0u8; SEED];
    let mut s1 = [0u8; SEED];
    s0.copy_from_slice(&random[..SEED]);
    s1.copy_from_slice(&random[SEED..]);
    let (root0, root1) = (s0, s1);
    let (mut t0, mut t1) = (false, true);
    let mut levels = Vec::with_capacity(depth);
    for i in 0..depth {
        let (l0, tl0, r0, tr0) = expand(&s0);
        let (l1, tl1, r1, tr1) = expand(&s1);
        let a = bit(alpha, i, depth);
        let seed_cw = if a { xor_seed(&l0, &l1) } else { xor_seed(&r0, &r1) };
        let left = tl0 ^ tl1 ^ a ^ true;
        let right = tr0 ^ tr1 ^ a;
        let (k0, kt0, k1, kt1, keep_cw) = if a { (r0, tr0, r1, tr1, right) } else { (l0, tl0, l1, tl1, left) };
        s0 = if t0 { xor_seed(&k0, &seed_cw) } else { k0 };
        s1 = if t1 { xor_seed(&k1, &seed_cw) } else { k1 };
        let nt0 = kt0 ^ (t0 & keep_cw);
        let nt1 = kt1 ^ (t1 & keep_cw);
        t0 = nt0;
        t1 = nt1;
        levels.push(Correction { seed: seed_cw, left, right });
    }
    let mut last = convert(&s0, beta.len());
    xor_into(&mut last, &convert(&s1, beta.len()));
    xor_into(&mut last, beta);
    let mut check = leaf_proof(alpha, &s0);
    xor_into(&mut check, &leaf_proof(alpha, &s1));
    Some((
        Key { party: false, seed: root0, levels: levels.clone(), check, last: last.clone() },
        Key { party: true, seed: root1, levels, check, last },
    ))
}

/// One server's share of slot `x`.
#[must_use]
pub fn eval(key: &Key, x: u64) -> Vec<u8> {
    let (s, t) = walk(key, x);
    let mut out = convert(&s, key.last.len());
    if t {
        xor_into(&mut out, &key.last);
    }
    out
}

/// One server's share of every slot, in slot order: what a server adds into its round table for one client.
#[must_use]
pub fn eval_all(key: &Key) -> Vec<Vec<u8>> {
    (0..1u64 << key.levels.len()).map(|x| eval(key, x)).collect()
}

/// One server's share of every slot and its proof. The two servers compare proofs; equal proofs mean the pair writes one slot
/// at most, and the client is counted. Different proofs mean the client is dropped from the round.
#[must_use]
pub fn eval_all_verified(key: &Key) -> (Vec<Vec<u8>>, [u8; PROOF]) {
    let mut pi = [0u8; PROOF];
    let mut shares = Vec::with_capacity(1 << key.levels.len());
    for x in 0..1u64 << key.levels.len() {
        let (s, t) = walk(key, x);
        let mut leaf = leaf_proof(x, &s);
        if t {
            xor_into(&mut leaf, &key.check);
        }
        fold_proof(&mut pi, &leaf);
        let mut out = convert(&s, key.last.len());
        if t {
            xor_into(&mut out, &key.last);
        }
        shares.push(out);
    }
    (shares, pi)
}

/// One server's half of a round: its table share from every client whose proof the other server matched. `peer_proofs[i]` is
/// the other server's proof for `keys[i]`. Returns the table share and which clients counted.
#[must_use]
pub fn server_round(keys: &[Key], own_proofs: &[[u8; PROOF]], peer_proofs: &[[u8; PROOF]], shares: &[Vec<Vec<u8>>]) -> (Vec<Vec<u8>>, Vec<bool>) {
    let slots = shares.first().map_or(0, Vec::len);
    let width = shares.first().and_then(|s| s.first()).map_or(0, Vec::len);
    let mut table = vec![vec![0u8; width]; slots];
    let mut counted = Vec::with_capacity(keys.len());
    for i in 0..keys.len() {
        let ok = own_proofs.get(i).is_some() && own_proofs.get(i) == peer_proofs.get(i) && shares[i].len() == slots;
        counted.push(ok);
        if ok {
            for (row, share) in table.iter_mut().zip(&shares[i]) {
                xor_into(row, share);
            }
        }
    }
    (table, counted)
}

/// The published table: the two servers' shares added.
#[must_use]
pub fn combine(a: &[Vec<u8>], b: &[Vec<u8>]) -> Vec<Vec<u8>> {
    a.iter()
        .zip(b)
        .map(|(x, y)| {
            let mut r = x.clone();
            xor_into(&mut r, y);
            r
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random(n: u8) -> [u8; 2 * SEED] {
        let mut r = [0u8; 2 * SEED];
        blake3::Hasher::new_derive_key("dpf test randomness").update(&[n]).finalize_xof().fill(&mut r);
        r
    }

    #[test]
    fn the_two_shares_add_to_the_message_at_its_slot_and_to_zero_everywhere_else() {
        for depth in [1usize, 3, 8] {
            for alpha in [0u64, (1 << depth) - 1, (1 << depth) / 3] {
                let beta: Vec<u8> = (0..40u8).collect();
                let (k0, k1) = gen(alpha, &beta, depth, &random(depth as u8 ^ alpha as u8)).unwrap();
                for x in 0..1u64 << depth {
                    let mut y = eval(&k0, x);
                    xor_into(&mut y, &eval(&k1, x));
                    if x == alpha {
                        assert_eq!(y, beta, "depth {depth}: slot {x} must hold the message");
                    } else {
                        assert!(y.iter().all(|b| *b == 0), "depth {depth}: slot {x} must add to zero");
                    }
                }
            }
        }
    }

    #[test]
    fn one_share_alone_shows_no_message_anywhere() {
        let beta = vec![0xAAu8; 64];
        let (k0, _) = gen(5, &beta, 4, &random(9)).unwrap();
        for x in 0..16 {
            assert_ne!(eval(&k0, x), beta, "one server's share must never equal the message");
        }
    }

    #[test]
    fn a_write_of_nothing_is_the_same_shape_as_a_real_write() {
        let real = gen(7, &[0x55u8; 100], 5, &random(1)).unwrap();
        let none = gen(0, &[0u8; 100], 5, &random(2)).unwrap();
        assert_eq!(real.0.wire_len(), none.0.wire_len());
        assert_eq!(real.0.to_bytes().len(), none.1.to_bytes().len());
        // and it writes nothing anywhere
        for x in 0..32 {
            let mut y = eval(&none.0, x);
            xor_into(&mut y, &eval(&none.1, x));
            assert!(y.iter().all(|b| *b == 0));
        }
    }

    #[test]
    fn a_key_survives_the_wire_and_a_wrong_shape_is_refused() {
        let (k0, k1) = gen(3, &[1u8; 24], 3, &random(4)).unwrap();
        assert_eq!(Key::from_bytes(&k0.to_bytes(), 3, 24), Some(k0.clone()));
        assert_eq!(Key::from_bytes(&k1.to_bytes(), 3, 24), Some(k1));
        let b = k0.to_bytes();
        assert_eq!(Key::from_bytes(&b, 4, 24), None, "a key for another depth is refused");
        assert_eq!(Key::from_bytes(&b[..b.len() - 1], 3, 24), None, "a short key is refused");
        let mut bad = b.clone();
        bad[0] = 2;
        assert_eq!(Key::from_bytes(&bad, 3, 24), None, "a party byte other than 0 or 1 is refused");
    }

    #[test]
    fn a_tampered_key_does_not_deliver_the_message() {
        let beta = vec![0x42u8; 32];
        let (k0, k1) = gen(2, &beta, 3, &random(6)).unwrap();
        let mut b = k1.to_bytes();
        b[5] ^= 1; // one bit of the root seed
        let k1t = Key::from_bytes(&b, 3, 32).unwrap();
        let mut y = eval(&k0, 2);
        xor_into(&mut y, &eval(&k1t, 2));
        assert_ne!(y, beta, "a tampered key must not deliver the message");
    }

    #[test]
    fn an_honest_pair_proves_itself_and_a_mixed_pair_does_not() {
        let (a0, a1) = gen(3, &[7u8; 48], 4, &random(10)).unwrap();
        let (b0, b1) = gen(3, &[7u8; 48], 4, &random(11)).unwrap();
        assert_eq!(eval_all_verified(&a0).1, eval_all_verified(&a1).1, "an honest pair's proofs must agree");
        assert_eq!(eval_all_verified(&b0).1, eval_all_verified(&b1).1);
        assert_ne!(eval_all_verified(&a0).1, eval_all_verified(&b1).1, "keys from two different pairs must not prove");
        let (n0, n1) = gen(0, &[0u8; 48], 4, &random(12)).unwrap();
        assert_eq!(eval_all_verified(&n0).1, eval_all_verified(&n1).1, "a write of nothing proves like any write");
    }

    /// The attack the proof exists for: a client edits a correction word in both keys alike, so the pair writes in many slots at
    /// once and would scribble over other people's payments. It must not prove.
    #[test]
    fn a_pair_that_writes_more_than_one_slot_is_refused() {
        let (mut k0, mut k1) = gen(5, &[9u8; 32], 4, &random(13)).unwrap();
        k0.levels[1].seed[0] ^= 0x80;
        k1.levels[1].seed[0] ^= 0x80;
        let written = (0..16u64)
            .filter(|x| {
                let mut y = eval(&k0, *x);
                xor_into(&mut y, &eval(&k1, *x));
                y.iter().any(|b| *b != 0)
            })
            .count();
        assert!(written > 1, "CALIBRATION: the edit must make the pair write more than one slot ({written})");
        assert_ne!(eval_all_verified(&k0).1, eval_all_verified(&k1).1, "a pair writing {written} slots must not prove");
    }

    #[test]
    fn a_round_publishes_every_honest_write_and_drops_a_cheat() {
        let depth = 3;
        let width = 40;
        // one payment at slot 6, two nodes writing nothing, and one cheat scribbling over several slots
        let mut pairs = vec![
            gen(6, &[0xC3u8; 40], depth, &random(20)).unwrap(),
            gen(0, &[0u8; 40], depth, &random(21)).unwrap(),
            gen(0, &[0u8; 40], depth, &random(22)).unwrap(),
        ];
        let (mut c0, mut c1) = gen(2, &[0x11u8; 40], depth, &random(23)).unwrap();
        c0.levels[0].seed[3] ^= 1;
        c1.levels[0].seed[3] ^= 1;
        pairs.push((c0, c1));
        let keys0: Vec<Key> = pairs.iter().map(|p| p.0.clone()).collect();
        let keys1: Vec<Key> = pairs.iter().map(|p| p.1.clone()).collect();
        let (sh0, pr0): (Vec<_>, Vec<_>) = keys0.iter().map(eval_all_verified).unzip();
        let (sh1, pr1): (Vec<_>, Vec<_>) = keys1.iter().map(eval_all_verified).unzip();
        let (t0, counted0) = server_round(&keys0, &pr0, &pr1, &sh0);
        let (t1, counted1) = server_round(&keys1, &pr1, &pr0, &sh1);
        assert_eq!(counted0, vec![true, true, true, false], "the cheat must be dropped by server 0");
        assert_eq!(counted0, counted1, "both servers must drop the same clients");
        let table = combine(&t0, &t1);
        assert_eq!(table.len(), 1 << depth);
        for (x, row) in table.iter().enumerate() {
            if x == 6 {
                assert_eq!(row, &vec![0xC3u8; width], "the payment must appear at its slot");
            } else {
                assert!(row.iter().all(|b| *b == 0), "slot {x} must be empty: no cheat's write survives");
            }
        }
        // and no single server's share holds the payment anywhere
        assert!(t0.iter().all(|row| row != &vec![0xC3u8; width]));
    }

    /// The cost of one client's write at the real shape: 8 slots (one block's spend lane) of 500 KB (one measured transaction).
    /// Run with `--ignored`; it prints the measured key size and one server's evaluation time.
    #[test]
    #[ignore]
    fn measure_a_real_sized_write() {
        let slot = 500 * 1024;
        let (k0, k1) = gen(5, &vec![0x5Au8; slot], 3, &random(30)).unwrap();
        let t = std::time::Instant::now();
        let (_, p0) = eval_all_verified(&k0);
        let one = t.elapsed();
        let (_, p1) = eval_all_verified(&k1);
        assert_eq!(p0, p1);
        eprintln!("[dpf-measure] key {} B per server; one server evaluates and proves one client in {:?}", k0.wire_len(), one);
    }

    #[test]
    fn a_slot_outside_the_table_is_refused() {
        assert!(gen(8, &[0u8; 8], 3, &random(7)).is_none());
        assert!(gen(0, &[0u8; 8], 0, &random(7)).is_none());
    }
}
