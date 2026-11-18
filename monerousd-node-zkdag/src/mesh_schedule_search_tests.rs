// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE FULL-ALPHABET SEARCH — every layer of node operation, random schedules, every property.**
//!
//! `fold_schedule_fuzz_tests` searches the four events that first broke the fold. This file searches the
//! WHOLE alphabet the scenario engine now speaks — production, out-of-order and burst delivery, lost
//! deliveries that only a parent ask can repair, restarts through the checkpoint, jumps by certified
//! bundle, real-note receives, forgotten cover bytes that must regenerate, and the adversary: tampered
//! bundles, forged page rows, wrong-work blocks, replayed bundles — and asserts EVERY property the engine
//! knows: no honest block refused, agreement on every record's ordinal / the counter / the spine root /
//! the unspent root / the selected tip, the genesis row intact, every party READY (no orphans, no stale
//! spine, no sidecar gap, no missing record, serving), every real record held everywhere at the same
//! ordinal, and a carry bounded by depth × width. An adversarial action that is NOT refused fails the
//! schedule on the spot.
//!
//! The drain emulates the mesh's own repair paths — parent asks, sidecar pages, roots runs — because a
//! restarted node holds its anchor's past only as shells and a jumped node holds its certified prefix
//! only as coordinates: "everyone holds everything" is reached the way the mesh reaches it, or not at all.
//!
//! ⛔ SCOPE: in-process island. Proves nothing about the onion transport, per-node cost or scale; the
//! live pair gate and the multi-device run at the scale floor remain the only network proofs.
//!
//! A find prints the seed and the script in the case-file grammar: paste it into
//! `consensus_scenarios.txt` and the class is permanent coverage.

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use crate::consensus_scenarios::{Act, Sim};

    fn as_case(name: &str, parties: usize, script: &[Act]) -> String {
        let mut out = format!("name {name}\nparties {parties}\n");
        for a in script {
            out.push_str(&match a {
                Act::Produce(i, n) => format!("produce {i} {n}\n"),
                Act::Deliver(k) => format!("deliver {k}\n"),
                Act::Drain => "drain\n".to_string(),
                Act::Restart(i) => format!("restart {i}\n"),
                Act::Jump(i, j) => format!("jump {i} {j}\n"),
                Act::Burst(k) => format!("burst {k}\n"),
                Act::Drop(i) => format!("drop {i}\n"),
                Act::Receive(i) => format!("receive {i}\n"),
                Act::Forget(i) => format!("forget {i}\n"),
                Act::Tamper(i, j) => format!("tamper {i} {j}\n"),
                Act::ForgeRows(i) => format!("forge-rows {i}\n"),
                Act::Invalid(i) => format!("invalid {i}\n"),
                Act::Replay(i, j) => format!("replay {i} {j}\n"),
                Act::Spend(i) => format!("spend {i}\n"),
            });
        }
        out
    }

    /// One action from the whole alphabet, weighted toward the honest mesh with a steady adversary.
    fn roll(sim: &mut Sim, parties: usize) -> Act {
        let r = sim.rand(100);
        let i = sim.rand(parties);
        let j = sim.rand(parties);
        if r < 30 {
            Act::Produce(i, 1)
        } else if r < 50 {
            Act::Deliver(sim.rand(64))
        } else if r < 58 {
            Act::Burst(1 + sim.rand(6))
        } else if r < 63 {
            Act::Drop(i)
        } else if r < 71 {
            Act::Restart(i)
        } else if r < 77 {
            Act::Jump(i, j)
        } else if r < 81 {
            Act::Receive(i)
        } else if r < 84 {
            Act::Spend(i)
        } else if r < 87 {
            Act::Forget(i)
        } else if r < 91 {
            Act::Tamper(i, j)
        } else if r < 94 {
            Act::ForgeRows(i)
        } else if r < 97 {
            Act::Invalid(i)
        } else {
            Act::Replay(i, j)
        }
    }

    fn search(name: &str, parties: usize, seeds: std::ops::RangeInclusive<u64>, steps: usize, salt: u64) {
        for seed in seeds {
            let mut sim = Sim::new(parties, seed.wrapping_mul(salt));
            for _ in 0..steps {
                let a = roll(&mut sim, parties);
                if let Err(why) = sim.step_checked(a) {
                    panic!(
                        "{name} — seed {seed}: an adversarial action was NOT refused: {why}\n\
                         paste this into consensus_scenarios.txt:\n\n{}",
                        as_case(&format!("found-{name}-seed-{seed}"), parties, &sim.trace)
                    );
                }
            }
            sim.drain();
            if let Err(why) = sim.verdict() {
                panic!(
                    "{name} — seed {seed}: {why}\n\
                     paste this into consensus_scenarios.txt:\n\n{}",
                    as_case(&format!("found-{name}-seed-{seed}"), parties, &sim.trace)
                );
            }
        }
    }

    /// ⭐⭐⭐ THE SEARCH over every layer: two, three and four parties.
    #[test]
    fn every_layer_of_node_operation_under_random_schedules_leaves_every_party_ready_and_agreeing() {
        search("two-parties", 2, 1..=10, 48, 0x9E37_79B9_7F4A_7C15);
        search("three-parties", 3, 1..=8, 48, 0xC2B2_AE3D_27D4_EB4F);
        search("four-parties", 4, 1..=4, 40, 0x1656_67B1_9E37_79F9);
    }

    /// The search's three-party seed 5 alone (lane stable 2026-11-01, stable/b1.log: "party 0 does not hold real record …"),
    /// so the class it found replays in seconds while it is worked; the search above keeps running every seed.
    #[test]
    fn three_parties_seed_5_holds_every_real_record_everywhere() {
        search("three-parties", 3, 5..=5, 48, 0xC2B2_AE3D_27D4_EB4F);
    }

    /// The adversary alone, against a converging honest mesh: every tamper, forgery, invalid block and
    /// replay must be refused with no state moved, while the honest parties keep agreeing.
    #[test]
    fn the_adversary_is_refused_at_every_layer_while_honest_parties_keep_agreeing() {
        let parties = 3usize;
        for seed in 1..=6u64 {
            let mut sim = Sim::new(parties, seed.wrapping_mul(0xA24B_AED4_963E_E407));
            for round in 0..12 {
                for i in 0..parties {
                    sim.step(Act::Produce(i, 1));
                }
                sim.step(Act::Burst(4));
                let i = sim.rand(parties);
                let j = (i + 1 + sim.rand(parties - 1)) % parties;
                let attack = match round % 4 {
                    0 => Act::Tamper(i, j),
                    1 => Act::ForgeRows(i),
                    2 => Act::Invalid(i),
                    _ => Act::Replay(i, j),
                };
                if let Err(why) = sim.step_checked(attack.clone()) {
                    panic!(
                        "adversary — seed {seed}: {attack:?} was NOT refused: {why}\n\n{}",
                        as_case(&format!("found-adversary-seed-{seed}"), parties, &sim.trace)
                    );
                }
                if round % 3 == 2 {
                    sim.step(Act::Jump(j, i));
                }
            }
            sim.drain();
            if let Err(why) = sim.verdict() {
                panic!(
                    "adversary — seed {seed}: {why}\n\n{}",
                    as_case(&format!("found-adversary-seed-{seed}"), parties, &sim.trace)
                );
            }
        }
    }

    /// Real money through every seam: receives land on every party at the same ordinal, byte for byte,
    /// across restarts, jumps, lost deliveries and forgotten cover.
    #[test]
    fn real_notes_survive_every_seam_and_are_held_everywhere() {
        let parties = 3usize;
        for seed in 1..=8u64 {
            let mut sim = Sim::new(parties, seed.wrapping_mul(0xD6E8_FEB8_6659_FD93));
            for round in 0..10 {
                let i = sim.rand(parties);
                sim.step(Act::Receive(i));
                sim.step(Act::Produce((i + 1) % parties, 2));
                let p = sim.rand(parties);
                match round % 6 {
                    0 => sim.step(Act::Drop(p)),
                    1 => sim.step(Act::Restart(p)),
                    2 => sim.step(Act::Jump(p, (p + 1) % parties)),
                    3 => sim.step(Act::Forget(p)),
                    4 => {
                        sim.step(Act::Burst(6));
                        if let Err(why) = sim.step_checked(Act::Spend(p)) {
                            panic!("real-notes — seed {seed}: {why}\n\n{}", as_case(&format!("found-real-notes-seed-{seed}"), parties, &sim.trace));
                        }
                    }
                    _ => sim.step(Act::Burst(3)),
                }
            }
            sim.drain();
            if let Err(why) = sim.verdict() {
                panic!(
                    "real-notes — seed {seed}: {why}\n\n{}",
                    as_case(&format!("found-real-notes-seed-{seed}"), parties, &sim.trace)
                );
            }
        }
    }
}
