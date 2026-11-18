// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The node's bounded view of the mix, and how a route is chosen from it.
//!
//! BORROWED: Bitcoin's `addrman` source buckets and its preference for addresses it has known longest, Tor's Guard flag's
//! reward for time on the network, Loopix's relay choice. No bandwidth weights: Tor's are gameable (TorMult), and a mix
//! sends one packet size at one rate.
//!
//! What this stops and what it does not. With no IP on the layer there is no address block to count by, so Tor's /16 rule
//! cannot exist here. Identity work and epoch rent make each identity cost something, a source cap limits what one
//! neighbour can introduce, age weight favours what has been around, and a full view drops its youngest first. A patient,
//! funded adversary still reaches its proportional share after a month, and a pin states exactly that.

use super::carrier::CarrierAddr;
use super::packet::{Hop, NodeId, HOPS};
use super::record::{id_of, Record};
use super::rng::Rng;
use std::collections::HashMap;

/// O1-FOOTPRINT-REVIEWED: at most 1,024 signed records of at most about 7.6 KB, whatever the size of the network.
pub const VIEW_MAX: usize = 1024;
/// How many identities one neighbour can introduce to the view.
pub const SOURCE_MAX: usize = 32;
/// An identity's weight grows by one a day to this limit: past a month, age buys nothing more.
const AGE_WEIGHT_DAYS_MAX: u64 = 30;
const DAY_MS: u64 = 86_400_000;

pub struct Entry {
    pub record: Record,
    pub raw: Vec<u8>,
    pub first_seen_ms: u64,
    source: NodeId,
}

pub struct View {
    /// Whether a Unix path is believable: only on a node that itself listens on one. A public node refuses them, so a
    /// hostile record cannot make it dial its own local sockets.
    allow_unix: bool,
    own: NodeId,
    /// O5: this node's own hop identity, when it is a hop through a gateway. It is this node: never a relay in its own routes,
    /// never a cover or cell destination of its own, never dropped to make room, never handed out as a sample.
    alias: Option<NodeId>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `VIEW_MAX`.
    entries: HashMap<NodeId, Entry>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    /// Newly seen or a newer sequence: tell the neighbours.
    New,
    /// Already held at this sequence or newer.
    Old,
    /// A local path on a public node, a neighbour past its share, or a full view that will not give up its older entries.
    Refused,
}

impl View {
    pub fn new(own: NodeId, allow_unix: bool) -> Self {
        View { allow_unix, own, alias: None, entries: HashMap::new() }
    }

    /// Names this node's hop identity (O5), or none. The old one, if any, leaves the view: it is no one's now.
    pub fn set_alias(&mut self, alias: Option<NodeId>) {
        if let Some(old) = self.alias {
            if Some(old) != alias {
                self.entries.remove(&old);
            }
        }
        self.alias = alias;
    }

    /// Whether an id is this node, under either of its names.
    pub fn is_self(&self, id: &NodeId) -> bool {
        *id == self.own || Some(*id) == self.alias
    }

    /// O5: the gateway a hop is reached through, when every carrier its record names is a `Via` (it has no address of its own).
    pub fn via_of(&self, id: &NodeId) -> Option<NodeId> {
        let e = self.entries.get(id)?;
        if e.record.carriers.iter().any(CarrierAddr::dialable) {
            return None;
        }
        e.record.carriers.iter().find_map(|c| match c {
            CarrierAddr::Via(g) => Some(*g),
            _ => None,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, id: &NodeId) -> Option<&Entry> {
        self.entries.get(id)
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    /// The door behind `verify_record`: local paths, sequence, source share, bound. `first_seen_ms` is `now_ms` for a
    /// record off the wire, and the saved time for this node's own file at boot.
    pub fn admit(&mut self, record: Record, raw: Vec<u8>, now_ms: u64, first_seen_ms: u64, source: NodeId) -> Admit {
        if !self.allow_unix && record.carriers.iter().any(|c| matches!(c, CarrierAddr::Unix(_))) {
            return Admit::Refused;
        }
        let id = id_of(&record.dsa_pk);
        if let Some(old) = self.entries.get_mut(&id) {
            if (record.epoch, record.seq) <= (old.record.epoch, old.record.seq) {
                return Admit::Old;
            }
            old.record = record;
            old.raw = raw;
            return Admit::New;
        }
        // A node introducing itself is first-hand, and counts against no one's share.
        if source != id {
            let held = self.entries.values().filter(|e| e.source == source).count();
            if held >= SOURCE_MAX {
                return Admit::Refused;
            }
        }
        if self.entries.len() >= VIEW_MAX && !self.make_room(now_ms) {
            return Admit::Refused;
        }
        self.entries.insert(id, Entry { record, raw, first_seen_ms, source });
        Admit::New
    }

    /// Makes room by dropping the youngest identity. Old entries outlast a flood of new ones.
    fn make_room(&mut self, now_ms: u64) -> bool {
        let victim = self.entries.iter().filter(|(id, _)| !self.is_self(id)).max_by_key(|(_, e)| e.first_seen_ms).map(|(id, e)| (*id, e.first_seen_ms));
        match victim {
            // A newcomer never displaces something seen this very moment; that would let a flood churn itself in.
            Some((_, seen)) if seen >= now_ms => false,
            Some((id, _)) => {
                self.entries.remove(&id);
                true
            }
            None => false,
        }
    }

    /// Everything that can carry a packet now: a current key, and an address to reach it by.
    fn routable(&self, now_epoch: u64) -> Vec<&Entry> {
        self.entries.values().filter(|e| e.record.epoch + 1 >= now_epoch && !e.record.carriers.is_empty()).collect()
    }

    fn weight(e: &Entry, now_ms: u64) -> u64 {
        1 + (now_ms.saturating_sub(e.first_seen_ms) / DAY_MS).min(AGE_WEIGHT_DAYS_MAX)
    }

    pub fn routable_count(&self, now_epoch: u64) -> usize {
        self.routable(now_epoch).len()
    }

    /// The crowd a sender hides in: relays that can carry a packet now and that this node has known for at least a day. Every relay
    /// sends at a constant rate, so each one is an equally likely origin of any packet; a relay counts only after a day so that a
    /// burst of fresh records (a sybil) cannot make a small crowd look large.
    pub fn crowd(&self, now_epoch: u64, now_ms: u64) -> usize {
        self.routable(now_epoch).iter().filter(|e| now_ms.saturating_sub(e.first_seen_ms) >= DAY_MS).count()
    }

    /// A destination other than this node, chosen uniformly among everything routable. `None` if there is no one else.
    pub fn random_other(&self, now_epoch: u64, rng: &mut Rng) -> Option<NodeId> {
        let all: Vec<NodeId> = self.routable(now_epoch).iter().map(|e| id_of(&e.record.dsa_pk)).filter(|i| !self.is_self(i)).collect();
        if all.is_empty() {
            return None;
        }
        Some(all[rng.below(all.len())])
    }

    /// Up to `n` destinations for cells. Rendezvous hashing over the epoch: a node cannot choose who receives its cells to
    /// shape the graph, and the choice moves each epoch.
    pub fn fanout(&self, now_epoch: u64, n: usize) -> Vec<NodeId> {
        let mut all: Vec<([u8; 32], NodeId)> = self
            .routable(now_epoch)
            .iter()
            .map(|e| id_of(&e.record.dsa_pk))
            .filter(|i| !self.is_self(i))
            .map(|i| {
                let mut h = blake3::Hasher::new_derive_key("monerousd mix v1 fanout");
                h.update(&self.own);
                h.update(&now_epoch.to_le_bytes());
                h.update(&i);
                (*h.finalize().as_bytes(), i)
            })
            .collect();
        all.sort();
        all.into_iter().take(n).map(|(_, i)| i).collect()
    }

    /// Three relays and the destination, each with an exponential delay drawn here. Relays are weighted by age and not
    /// repeated while another is left. The route never includes this node or the destination as a relay while anyone else
    /// can serve; a network of two has no one else, and it has no anonymity to protect.
    pub fn route(&self, dest: &NodeId, now_ms: u64, mean_delay_ms: f64, rng: &mut Rng) -> Option<Vec<Hop>> {
        let now_epoch = super::record::epoch_now(now_ms);
        let all = self.routable(now_epoch);
        let dest_entry = self.entries.get(dest)?;
        if dest_entry.record.epoch + 1 < now_epoch {
            return None;
        }
        let others: Vec<&Entry> = all.iter().copied().filter(|e| { let i = id_of(&e.record.dsa_pk); !self.is_self(&i) && i != *dest }).collect();
        let pool: &[&Entry] = if others.is_empty() { &all } else { &others };
        if pool.is_empty() {
            return None;
        }
        let mut hops: Vec<&Entry> = Vec::with_capacity(HOPS);
        for _ in 0..HOPS - 1 {
            let fresh: Vec<&Entry> = pool.iter().copied().filter(|e| !hops.iter().any(|h| std::ptr::eq(*h, *e))).collect();
            let from: &[&Entry] = if fresh.is_empty() { pool } else { &fresh };
            let total: u64 = from.iter().map(|e| Self::weight(e, now_ms)).sum();
            let mut pick = rng.u64() % total;
            let mut chosen = None;
            for e in from {
                let w = Self::weight(e, now_ms);
                if pick < w {
                    chosen = Some(*e);
                    break;
                }
                pick -= w;
            }
            hops.push(chosen?);
        }
        hops.push(dest_entry);
        Some(hops.iter().map(|e| Hop { id: id_of(&e.record.dsa_pk), kem_pk: e.record.kem_pk.clone(), delay_ms: rng.exp_ms(mean_delay_ms) }).collect())
    }

    /// The addresses this node can try for a neighbour.
    pub fn carriers_of(&self, id: &NodeId) -> Vec<CarrierAddr> {
        match self.entries.get(id) {
            Some(e) => e.record.carriers.clone(),
            None => Vec::new(),
        }
    }

    /// Everyone this node could hold a link to: a carrier it can dial. A hop through a gateway (`Via` only) is reached through
    /// that gateway, never dialled.
    pub fn neighbours(&self) -> Vec<NodeId> {
        self.entries.iter().filter(|(i, e)| !self.is_self(i) && e.record.carriers.iter().any(CarrierAddr::dialable)).map(|(i, _)| *i).collect()
    }

    /// Signed records to hand a neighbour as a sample: never this node's own hop record, which only its gateway may learn
    /// first-hand (a hop record arriving on any other link would tie that link's address to the hop).
    pub fn sample_raws(&self) -> Vec<Vec<u8>> {
        self.entries.iter().filter(|(i, _)| Some(**i) != self.alias).map(|(_, e)| e.raw.clone()).collect()
    }
}

// TWO-PARTY-REVIEWED: these pins measure one node's choice over a table it holds, which has no second side. The crossing is
// `mix_cut.py` on real processes; a Sybil run on real processes is listed as unproven in the spec.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqmix::record::DSA_PK;
    use std::collections::HashSet;

    /// A record admitted as if it had passed `verify_record`. These pins are about the choice, which reads only admitted
    /// entries; the door's refusals, work included, are pinned in `record.rs`.
    fn rec(n: u64, epoch: u64) -> Record {
        let mut dsa_pk = vec![0u8; DSA_PK];
        dsa_pk[..8].copy_from_slice(&n.to_le_bytes());
        let seq_addr = format!("192.0.2.1:{}", 1000 + (n as u32 % 60_000));
        Record {
            dsa_pk,
            epoch,
            kem_pk: vec![n as u8; crate::pqmix::packet::KEM_PK],
            carriers: vec![CarrierAddr::Relay(seq_addr)],
            seq: 1,
            pow_nonce: 0,
            epoch_nonce: 0,
        }
    }

    const NOW: u64 = 3_600_000 / 2; // inside epoch 0

    fn admit(v: &mut View, r: Record, at: u64, source: NodeId) -> (NodeId, Admit) {
        let id = id_of(&r.dsa_pk);
        (id, v.admit(r, vec![0u8; 16], at, at, source))
    }

    fn first_hand(v: &mut View, r: Record, at: u64) -> (NodeId, Admit) {
        let id = id_of(&r.dsa_pk);
        admit(v, r, at, id)
    }

    /// The honest measure of a choice: the share of relay positions, and of whole routes, an adversary's set holds.
    fn share(v: &View, dest: &NodeId, bad: &HashSet<NodeId>, now: u64) -> (f64, f64) {
        let mut rng = Rng::new();
        const N: usize = 20_000;
        let (mut hits, mut whole) = (0usize, 0usize);
        for _ in 0..N {
            let r = v.route(dest, now, 40.0, &mut rng).unwrap();
            let k = r[..HOPS - 1].iter().filter(|h| bad.contains(&h.id)).count();
            hits += k;
            if k == HOPS - 1 {
                whole += 1;
            }
        }
        (hits as f64 / (N * (HOPS - 1)) as f64, whole as f64 / N as f64)
    }

    #[test]
    fn one_neighbour_cannot_introduce_more_than_its_share_of_identities() {
        let own = [1u8; 32];
        let mut v = View::new(own, false);
        let liar = [7u8; 32];
        let mut admitted = 0;
        for i in 0..1000u64 {
            if admit(&mut v, rec(1000 + i, 0), NOW, liar).1 == Admit::New {
                admitted += 1;
            }
        }
        assert_eq!(admitted, SOURCE_MAX, "one neighbour introduced {admitted} identities");
        // A second neighbour has its own share: the cap is per neighbour, and that is its limit.
        for i in 0..1000u64 {
            admit(&mut v, rec(5000 + i, 0), NOW, [8u8; 32]);
        }
        assert_eq!(v.len(), 2 * SOURCE_MAX);
    }

    #[test]
    fn a_sybil_flood_through_three_neighbours_is_held_down_by_age_and_the_limit_is_stated() {
        let own = [1u8; 32];
        let mut v = View::new(own, false);
        let mut honest = Vec::new();
        for i in 0..20u64 {
            let (id, a) = first_hand(&mut v, rec(100 + i, 0), 0);
            assert_eq!(a, Admit::New);
            honest.push(id);
        }
        let now = 30 * DAY_MS;
        let current = crate::pqmix::record::epoch_now(now);
        // The honest records stay current in the fixture: age is what is being measured.
        let mut vv = View::new(own, false);
        for i in 0..20u64 {
            vv.admit(rec(100 + i, current), vec![], 0, 0, id_of(&rec(100 + i, 0).dsa_pk));
        }
        let mut v = vv;
        let mut bad = HashSet::new();
        for i in 0..1000u64 {
            let (id, a) = admit(&mut v, rec(1000 + i, current), now, [(i % 3) as u8 + 7; 32]);
            if a == Admit::New {
                bad.insert(id);
            }
        }
        assert_eq!(bad.len(), 3 * SOURCE_MAX);
        let (relay, whole) = share(&v, &honest[0], &bad, now);
        println!(
            "[mix] 96 new Sybils through 3 neighbours against 20 month-old honest nodes: {:.1} % of relay slots, {:.2} % of whole routes (uniform choice: 83 % and 56 %)",
            relay * 100.0,
            whole * 100.0
        );
        assert!(relay < 0.22, "new identities took {:.1} % of relay slots", relay * 100.0);
        assert!(whole < 0.03, "new identities took {:.2} % of whole routes", whole * 100.0);

        // THE LIMIT, stated as a pin: a month later those Sybils weigh the same as anyone and hold their share.
        let later = now + 31 * DAY_MS;
        let later_epoch = crate::pqmix::record::epoch_now(later);
        let mut aged = View::new(own, false);
        for i in 0..20u64 {
            aged.admit(rec(100 + i, later_epoch), vec![], 0, 0, id_of(&rec(100 + i, 0).dsa_pk));
        }
        for i in 0..96u64 {
            aged.admit(rec(1000 + i, later_epoch), vec![], now, now, [(i % 3) as u8 + 7; 32]);
        }
        let mut bad = HashSet::new();
        for i in 0..96u64 {
            bad.insert(id_of(&rec(1000 + i, 0).dsa_pk));
        }
        let (relay, _) = share(&aged, &honest[0], &bad, later);
        println!("[mix] the same Sybils a month later: {:.1} % of relay slots. These rules do not stop a patient adversary.", relay * 100.0);
        assert!(relay > 0.7, "the pin must say what the rules do not stop; measured {:.1} %", relay * 100.0);
    }

    #[test]
    fn a_flood_cannot_evict_older_entries_from_a_full_view() {
        let own = [1u8; 32];
        let mut v = View::new(own, false);
        let mut old = Vec::new();
        for i in 0..200u64 {
            let (id, a) = first_hand(&mut v, rec(100 + i, 0), 0);
            assert_eq!(a, Admit::New);
            old.push(id);
        }
        // Push far past the bound, each new identity first-hand, as a Sybil that dials in with each one would.
        for i in 0..(VIEW_MAX * 3) as u64 {
            first_hand(&mut v, rec(10_000 + i, 0), DAY_MS + i);
        }
        assert!(v.len() <= VIEW_MAX, "the view holds {} against a bound of {VIEW_MAX}", v.len());
        let kept = old.iter().filter(|i| v.get(i).is_some()).count();
        assert_eq!(kept, 200, "a flood evicted {} older entries", 200 - kept);
    }

    #[test]
    fn a_public_node_refuses_a_local_path_and_a_local_rig_accepts_it() {
        let mut r = rec(1, 0);
        r.carriers = vec![CarrierAddr::Unix("/tmp/x.sock".into())];
        let id = id_of(&r.dsa_pk);
        let mut public = View::new([1u8; 32], false);
        assert_eq!(public.admit(r.clone(), vec![], NOW, NOW, id), Admit::Refused);
        let mut rig = View::new([1u8; 32], true);
        assert_eq!(rig.admit(r, vec![], NOW, NOW, id), Admit::New);
    }

    #[test]
    fn a_newer_record_replaces_and_an_older_one_does_not() {
        let mut v = View::new([1u8; 32], false);
        let mut r = rec(5, 0);
        let id = id_of(&r.dsa_pk);
        assert_eq!(v.admit(r.clone(), vec![], NOW, NOW, id), Admit::New);
        assert_eq!(v.admit(r.clone(), vec![], NOW, NOW, id), Admit::Old);
        r.seq = 2;
        assert_eq!(v.admit(r.clone(), vec![], NOW, NOW, id), Admit::New);
        r.seq = 1;
        assert_eq!(v.admit(r, vec![], NOW, NOW, id), Admit::Old);
    }

    #[test]
    fn a_relay_is_never_this_node_or_the_destination_while_anyone_else_can_serve() {
        let own_rec = rec(0, 0);
        let own = id_of(&own_rec.dsa_pk);
        let mut v = View::new(own, false);
        first_hand(&mut v, own_rec, NOW);
        let (dest, _) = first_hand(&mut v, rec(1, 0), NOW);
        for i in 2..8u64 {
            first_hand(&mut v, rec(i, 0), NOW);
        }
        let mut rng = Rng::new();
        for _ in 0..2000 {
            let r = v.route(&dest, NOW, 40.0, &mut rng).unwrap();
            assert_eq!(r.last().unwrap().id, dest);
            let relays: HashSet<NodeId> = r[..HOPS - 1].iter().map(|h| h.id).collect();
            assert_eq!(relays.len(), HOPS - 1, "a relay was repeated while others were left");
            assert!(!relays.contains(&own) && !relays.contains(&dest));
        }
    }

    /// How the layer strengthens as nodes join: the entropy of a route's relay choice, printed at four sizes. A network of
    /// three has almost none, and this is a number to read, not a claim of anonymity.
    #[test]
    fn the_choice_gets_stronger_as_nodes_join() {
        let mut last = -1.0f64;
        for n in [3u64, 30, 300, 1000] {
            let own_rec = rec(0, 0);
            let own = id_of(&own_rec.dsa_pk);
            let mut v = View::new(own, false);
            first_hand(&mut v, own_rec, NOW);
            let mut dest = own;
            for i in 1..n {
                let (id, _) = first_hand(&mut v, rec(i, 0), NOW);
                dest = id;
            }
            let mut counts: HashMap<NodeId, u64> = HashMap::new();
            let mut rng = Rng::new();
            const R: u64 = 20_000;
            for _ in 0..R {
                let r = v.route(&dest, NOW, 40.0, &mut rng).unwrap();
                *counts.entry(r[1].id).or_insert(0) += 1;
            }
            let h: f64 = counts
                .values()
                .map(|c| {
                    let p = *c as f64 / R as f64;
                    -p * p.log2()
                })
                .sum();
            println!("[mix] {n} nodes: {h:.2} bits of choice at a relay position");
            assert!(h > last, "{n} nodes gave {h} bits, no more than {last}");
            last = h;
        }
    }
}
