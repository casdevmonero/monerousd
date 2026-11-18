// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE SEARCH — random schedules over the same engine the recorded cases use.**
//!
//! `consensus_scenarios` holds the classes we have already paid for: one case per gate run, replayable in
//! seconds. This file looks for the ones we have NOT paid for yet. Same engine, same property; the only
//! difference is that the script is generated from a seed instead of written down.
//!
//! When it finds something it prints the SEED and the exact action list, which is the case-file grammar —
//! so a discovery here is pasted straight into `consensus_scenarios.txt` and becomes permanent coverage.
//!
//! ⛔ SCOPE: in-process island. Proves nothing about the onion transport, per-node cost or scale; the live
//! pair gate and the multi-device run at the scale floor remain the only network proofs and are a
//! follow-on to every run here.

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use crate::consensus_scenarios::{Act, Sim};

    /// Print a generated script in the case-file grammar, so a find is pasted into the library as-is.
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

    /// ⭐⭐⭐ THE SEARCH. Random schedules over the four events that have broken the fold, with the
    /// property checked once the queue is empty.
    #[test]
    fn a_random_schedule_of_produce_deliver_restart_and_jump_leaves_every_party_agreeing() {
        let parties = 3usize;
        for seed in 1..=12u64 {
            let mut sim = Sim::new(parties, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            for _ in 0..40 {
                let roll = sim.rand(100);
                let a = if roll < 45 {
                    let i = sim.rand(parties);
                    Act::Produce(i, 1)
                } else if roll < 85 {
                    let k = sim.rand(64);
                    Act::Deliver(k)
                } else if roll < 95 {
                    let i = sim.rand(parties);
                    Act::Restart(i)
                } else {
                    let i = sim.rand(parties);
                    let j = sim.rand(parties);
                    Act::Jump(i, j)
                };
                sim.step(a);
            }
            sim.drain();
            let verdict = sim.verdict();
            if let Err(why) = verdict {
                panic!(
                    "SCHEDULE FOUND A DIVERGENCE — seed {seed}: {why}\n\
                     paste this into consensus_scenarios.txt to keep it forever:\n\n{}",
                    as_case(&format!("found-seed-{seed}"), parties, &sim.trace)
                );
            }
        }
    }

    /// The narrow, brutal case the gate keeps failing on, SEARCHED rather than exemplified: parties
    /// restart through their checkpoints while blocks are still undelivered.
    #[test]
    fn restarts_interleaved_with_undelivered_blocks_never_split_the_record_space() {
        let parties = 3usize;
        for seed in 1..=8u64 {
            let mut sim = Sim::new(parties, seed.wrapping_mul(0xD1B5_4A32_D192_ED03));
            for round in 0..8 {
                for i in 0..parties {
                    sim.step(Act::Produce(i, 1));
                }
                let k = sim.rand(8);
                sim.step(Act::Deliver(k));
                sim.step(Act::Restart(round % parties));
            }
            sim.drain();
            let verdict = sim.verdict();
            if let Err(why) = verdict {
                panic!(
                    "RESTART SCHEDULE FOUND A DIVERGENCE — seed {seed}: {why}\n\
                     paste this into consensus_scenarios.txt:\n\n{}",
                    as_case(&format!("found-restart-seed-{seed}"), parties, &sim.trace)
                );
            }
        }
    }
}
