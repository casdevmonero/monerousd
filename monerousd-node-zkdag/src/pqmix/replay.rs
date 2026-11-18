// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The replay set: a Bloom filter per epoch key, thrown away with the key. BORROWED: Katzenpost's replay rotation.
//!
//! No false negatives: a tag it has seen is always refused. A false positive drops one honest packet, and the layers above
//! re-ask. At the relay cap of 512 packets/s for one 3,600 s epoch (1.84 M tags), 2^25 bits and 6 hashes give about 0.03 %.

const BITS_LOG2: u32 = 25;
const HASHES: usize = 6;

/// O1-FOOTPRINT-REVIEWED: 4 MiB per key and at most two keys, whatever the traffic.
pub struct ReplayBloom {
    words: Vec<u64>,
}

impl ReplayBloom {
    pub fn new() -> Self {
        ReplayBloom { words: vec![0u64; 1usize << (BITS_LOG2 - 6)] }
    }
}

impl Default for ReplayBloom {
    fn default() -> Self {
        Self::new()
    }
}

impl super::packet::ReplaySet for ReplayBloom {
    fn insert_new(&mut self, tag: &[u8; 32]) -> bool {
        let mut new = false;
        for i in 0..HASHES {
            let v = u32::from_le_bytes([tag[i * 4], tag[i * 4 + 1], tag[i * 4 + 2], tag[i * 4 + 3]]) >> (32 - BITS_LOG2);
            let (w, b) = ((v >> 6) as usize, 1u64 << (v & 63));
            if self.words[w] & b == 0 {
                new = true;
                self.words[w] |= b;
            }
        }
        new
    }
}

// TWO-PARTY-REVIEWED: this set belongs to one hop and has no second side. The cross-node refusal is the `mix-replay` attack
// row in scratchpad/net/attacks.txt, against real processes.
#[cfg(test)]
mod tests {
    use super::super::packet::ReplaySet;
    use super::*;

    #[test]
    fn a_tag_seen_once_is_always_refused_after() {
        let mut r = ReplayBloom::new();
        for i in 0u32..100_000 {
            let t = *blake3::hash(&i.to_le_bytes()).as_bytes();
            r.insert_new(&t);
        }
        for i in 0u32..100_000 {
            let t = *blake3::hash(&i.to_le_bytes()).as_bytes();
            assert!(!r.insert_new(&t), "tag {i} was seen and came back new");
        }
    }

    #[test]
    fn honest_loss_at_the_full_epoch_load_is_small() {
        let mut r = ReplayBloom::new();
        const LOAD: u32 = 1_843_200;
        for i in 0..LOAD {
            r.insert_new(blake3::hash(&i.to_le_bytes()).as_bytes());
        }
        let mut lost = 0u32;
        const PROBES: u32 = 200_000;
        for i in 0..PROBES {
            let t = *blake3::hash(&(LOAD + i).to_le_bytes()).as_bytes();
            let mut probe = ReplayBloom { words: Vec::new() };
            std::mem::swap(&mut probe.words, &mut r.words);
            let seen = (0..HASHES).all(|h| {
                let v = u32::from_le_bytes([t[h * 4], t[h * 4 + 1], t[h * 4 + 2], t[h * 4 + 3]]) >> (32 - BITS_LOG2);
                probe.words[(v >> 6) as usize] & (1u64 << (v & 63)) != 0
            });
            std::mem::swap(&mut probe.words, &mut r.words);
            if seen {
                lost += 1;
            }
        }
        let pct = lost as f64 * 100.0 / PROBES as f64;
        println!("[mix] replay set at a full epoch: {pct:.4} % of honest packets lost");
        assert!(pct < 0.5, "{pct} % of honest packets lost at the epoch cap");
    }
}
