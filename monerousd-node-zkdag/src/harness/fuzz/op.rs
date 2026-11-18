// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE OPERATION GRAMMAR — structure-aware, so the fuzzer spends its time in REACHABLE states.**
//!
//! Random bytes at a socket reach the first length check and die there. Generating at the TYPE level
//! means every step is a well-formed call at a real door, and the interesting question — *what does a
//! legal-looking sequence of legal-looking calls do to the invariants?* — is the only question the run
//! spends its budget on.
//!
//! The alphabet is deliberately the SAME text grammar as `consensus_scenarios.txt`, so a find is not a
//! harness artefact: it prints as a case file line-for-line and becomes permanent coverage the moment it
//! is pasted there.
//!
//! Two sub-grammars, and the split is the design:
//!   * **honest** — produce, deliver out of order, burst, drop, restart, jump, receive, spend, forget.
//!   * **hostile** — well-formed-but-adversarial: a tampered certified bundle, forged sidecar rows
//!     (the forged-deletion-set shape), a wrong-work block (the forged-work shape), a replayed bundle
//!     (the same-blob re-offer shape). A hostile op is an op whose ONLY correct outcome is refusal, so
//!     it carries its own verdict and needs no oracle to interpret it.
//!
//! ⛔ THE PARSER IS STRICT, AND THAT IS A FUND-SAFETY PROPERTY, NOT A STYLE CHOICE.
//!
//! ROOT-LAYER: the corpus decoder is where a recorded sequence's IDENTITY is produced. A tolerant
//! decoder that rescues a missing argument to `0` produces a DIFFERENT sequence than the one that was
//! recorded, and every consumer downstream — the shrinker's predicate, the regression replay, the
//! emitted reproducer — then reasons about a schedule that was never interesting. Rescuing at any
//! consumer cannot repair that: by then the wrong `Op` already exists. So arity is enforced HERE,
//! exactly once, and a line that does not carry its arguments is refused rather than repaired.
//! This is the same lesson as `chain_object::decode_exact` one layer down: one object, one encoding.
//! MEASURED: with the tolerant form, `"jump 1"` (a truncated two-argument op) parsed as `Jump(1, 0)` —
//! a DIFFERENT op that replays a different schedule; strict, it is refused and the corpus file is
//! skipped whole. `a_truncated_op_line_is_refused_rather_than_rescued` pins both halves.
//! MUST-STAY-GREEN: every well-formed corpus line still round-trips
//! (`a_corpus_entry_replays_the_recorded_sequence_on_two_independent_nodes`), and a corpus written by a
//! newer harness is skipped rather than mis-replayed.

use crate::consensus_scenarios::Act;

/// One scheduled operation against the multi-node in-process network.
///
/// Party indices are `u8` and are taken modulo the party count at execution, so a sequence stays
/// meaningful when the shrinker reduces the party count under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    // ---- honest mesh ----
    /// Party `i` produces `n` blocks back to back.
    Produce(u8, u8),
    /// Hand the `k`th owed block over NOW — out of order by construction.
    Deliver(u8),
    /// Hand the next `k` owed blocks over at once — the cascade shape the transport delivers.
    Burst(u8),
    /// Hand every owed block over until nothing is owed. A QUIESCENCE POINT.
    Drain,
    /// Lose one owed delivery to party `i` for good — only a repair path can recover it (partition).
    Drop(u8),
    /// Party `i` goes through its checkpoint: export, fresh process, restore.
    Restart(u8),
    /// Party `i` adopts party `j`'s certified bundle, the way a joiner does (DSYNC adopt).
    Jump(u8, u8),
    /// Party `i` produces a block carrying a REAL note — a receive, not regenerable cover.
    Receive(u8),
    /// Party `i` spends one real note it holds — a deletion carried by its next block.
    Spend(u8),
    /// Party `i` forgets the bytes of every idle record — they must regenerate from coordinates.
    Forget(u8),

    // ---- hostile: well-formed, adversarial, and refusal is the ONLY correct outcome ----
    /// Party `i` is offered a TAMPERED bundle from `j` (a spine that does not reproduce the certified root).
    Tamper(u8, u8),
    /// Party `i` is paged FORGED ROWS — invented record ids at real ordinals, carrying recv/del bytes.
    ForgeRows(u8),
    /// Party `i` gossips a block declaring work it did not do (the forged-work shape).
    Invalid(u8),
    /// Party `i` is re-sent the last bundle it adopted from `j` — a replay; no state may move.
    Replay(u8, u8),
}

impl Op {
    /// Is refusal the ONLY correct outcome of this op? A hostile op that changes ANY consensus-visible
    /// value is a finding on the spot — no oracle interpretation needed.
    pub fn is_hostile(self) -> bool {
        matches!(self, Op::Tamper(..) | Op::ForgeRows(..) | Op::Invalid(..) | Op::Replay(..))
    }

    /// Does the ACTOR of this hostile op legitimately mine and graft an honest block before it offers the
    /// forgery?
    ///
    /// PAST-CHATS-CHECKED: this is READ OFF the engine, not decided here. `Sim::invalid` produces a REAL
    /// block on party `i` ("the block the honest party just grafted is real"), queues it for every peer
    /// and pushes it into `blocks`, and only THEN forges a copy with `work * 8 + 1` to offer around. Its
    /// own assertion is correspondingly narrow: for every party, the FORGED block must not be `Added` and
    /// must not move `dag().tips()`. `Sim::tamper` and `Sim::replay` produce nothing and assert on a state
    /// digest; `Sim::forge_rows` produces nothing and asserts on the ordinal rows. So the engine already
    /// distinguishes "an op that mines" from "an op that only offers", and this method carries that
    /// existing distinction rather than inventing one. (A transcript search for the user's own words on
    /// forged-work blocks returned no session; the engine's own code is the governing prior art.)
    ///
    /// ⛔ THIS IS NOT A NARROWING OF THE CHECK. On an `Invalid` step the actor's DAG and selected tip
    /// legitimately advance because it really did mine, so demanding byte-identical state everywhere would
    /// fire on the HONEST half of the action on every single `Invalid` and report a defect that is not
    /// there. The catalogue instead asserts, on the actor, that NOTHING WHICH HOLDS VALUE moved — the
    /// unspent set, its root and fold, the nullifier set and root, the accumulator, the membership tip —
    /// which is a property `Sim::invalid` does NOT check and is exactly what this lane adds. Peers get the
    /// full byte-identity demand, unchanged.
    pub fn actor_produces_an_honest_block(self) -> bool {
        matches!(self, Op::Invalid(_))
    }

    /// Ops after which the unspent set of ANY party is allowed to lose a member.
    ///
    /// `Spend` is the chain-recorded departure. `Jump` replaces state wholesale from a certified prefix,
    /// so its membership is the prefix's and not this node's history — exempt, and reported separately
    /// rather than silently allowed (see the oracle).
    pub fn may_remove_from_unspent(self) -> bool {
        matches!(self, Op::Spend(_) | Op::Jump(..))
    }

    /// Ops after which the unspent set of ANY party is allowed to gain a member.
    ///
    /// Everything that can carry a note into a node: producing it, receiving it, taking delivery of a
    /// block, restoring from the checkpoint, adopting a certified prefix. `Spend` is included because
    /// the deleting block is itself a block and carries its cover.
    ///
    /// ⛔ NOT `Drop`, `Forget`, or any hostile op. A commitment that enters the unspent set on one of
    /// those is a member with no namable chain-authorised justifier — I-1, exactly.
    pub fn may_add_to_unspent(self) -> bool {
        matches!(
            self,
            Op::Produce(..)
                | Op::Receive(_)
                | Op::Deliver(_)
                | Op::Burst(_)
                | Op::Drain
                | Op::Restart(_)
                | Op::Jump(..)
                | Op::Spend(_)
        )
    }

    /// The party this op names, if any — used by the shrinker to drop unreachable parties.
    pub fn party(self) -> Option<u8> {
        match self {
            Op::Produce(i, _)
            | Op::Deliver(i)
            | Op::Burst(i)
            | Op::Drop(i)
            | Op::Restart(i)
            | Op::Receive(i)
            | Op::Spend(i)
            | Op::Forget(i)
            | Op::ForgeRows(i)
            | Op::Invalid(i) => Some(i),
            Op::Jump(i, _) | Op::Tamper(i, _) | Op::Replay(i, _) => Some(i),
            Op::Drain => None,
        }
    }

    /// Lower into the scenario engine's action, clamping every party index into range.
    pub fn to_act(self, parties: usize) -> Act {
        let p = parties.max(1);
        let ix = |v: u8| (v as usize) % p;
        match self {
            Op::Produce(i, n) => Act::Produce(ix(i), 1 + (n as usize % 3)),
            Op::Deliver(k) => Act::Deliver(k as usize),
            Op::Burst(k) => Act::Burst(1 + (k as usize % 6)),
            Op::Drain => Act::Drain,
            Op::Drop(i) => Act::Drop(ix(i)),
            Op::Restart(i) => Act::Restart(ix(i)),
            Op::Jump(i, j) => Act::Jump(ix(i), ix(j)),
            Op::Receive(i) => Act::Receive(ix(i)),
            Op::Spend(i) => Act::Spend(ix(i)),
            Op::Forget(i) => Act::Forget(ix(i)),
            Op::Tamper(i, j) => Act::Tamper(ix(i), ix(j)),
            Op::ForgeRows(i) => Act::ForgeRows(ix(i)),
            Op::Invalid(i) => Act::Invalid(ix(i)),
            Op::Replay(i, j) => Act::Replay(ix(i), ix(j)),
        }
    }

    /// The case-file line for this op, in `consensus_scenarios.txt` grammar. A find pastes in verbatim.
    pub fn to_case_line(self, parties: usize) -> String {
        match self.to_act(parties) {
            Act::Produce(i, n) => format!("produce {i} {n}"),
            Act::Deliver(k) => format!("deliver {k}"),
            Act::Drain => "drain".to_string(),
            Act::Restart(i) => format!("restart {i}"),
            Act::Jump(i, j) => format!("jump {i} {j}"),
            Act::Burst(k) => format!("burst {k}"),
            Act::Drop(i) => format!("drop {i}"),
            Act::Receive(i) => format!("receive {i}"),
            Act::Forget(i) => format!("forget {i}"),
            Act::Tamper(i, j) => format!("tamper {i} {j}"),
            Act::ForgeRows(i) => format!("forge-rows {i}"),
            Act::Invalid(i) => format!("invalid {i}"),
            Act::Replay(i, j) => format!("replay {i} {j}"),
            Act::Spend(i) => format!("spend {i}"),
        }
    }

    /// The Rust literal for this op — what a generated reproducer contains.
    pub fn to_rust(self) -> String {
        match self {
            Op::Produce(i, n) => format!("Op::Produce({i}, {n})"),
            Op::Deliver(k) => format!("Op::Deliver({k})"),
            Op::Burst(k) => format!("Op::Burst({k})"),
            Op::Drain => "Op::Drain".to_string(),
            Op::Drop(i) => format!("Op::Drop({i})"),
            Op::Restart(i) => format!("Op::Restart({i})"),
            Op::Jump(i, j) => format!("Op::Jump({i}, {j})"),
            Op::Receive(i) => format!("Op::Receive({i})"),
            Op::Spend(i) => format!("Op::Spend({i})"),
            Op::Forget(i) => format!("Op::Forget({i})"),
            Op::Tamper(i, j) => format!("Op::Tamper({i}, {j})"),
            Op::ForgeRows(i) => format!("Op::ForgeRows({i})"),
            Op::Invalid(i) => format!("Op::Invalid({i})"),
            Op::Replay(i, j) => format!("Op::Replay({i}, {j})"),
        }
    }

    /// The corpus wire form: `kind` followed by EXACTLY the arguments the op carries — one, two, or none.
    /// No padding: a line's argument count is part of the op's identity, and [`Op::parse`] enforces it.
    pub fn to_corpus_line(self) -> String {
        match self {
            Op::Produce(i, n) => format!("produce {i} {n}"),
            Op::Deliver(k) => format!("deliver {k}"),
            Op::Burst(k) => format!("burst {k}"),
            Op::Drain => "drain".to_string(),
            Op::Drop(i) => format!("drop {i}"),
            Op::Restart(i) => format!("restart {i}"),
            Op::Jump(i, j) => format!("jump {i} {j}"),
            Op::Receive(i) => format!("receive {i}"),
            Op::Spend(i) => format!("spend {i}"),
            Op::Forget(i) => format!("forget {i}"),
            Op::Tamper(i, j) => format!("tamper {i} {j}"),
            Op::ForgeRows(i) => format!("forge-rows {i}"),
            Op::Invalid(i) => format!("invalid {i}"),
            Op::Replay(i, j) => format!("replay {i} {j}"),
        }
    }

    /// Parse one corpus line, STRICTLY.
    ///
    /// `None` for an unknown kind, a missing argument, an unparsable argument, or a trailing argument the
    /// op does not carry. Nothing is defaulted and nothing is ignored: a line either names exactly one op
    /// or it names none. See the module note for why the strictness lives at this layer.
    pub fn parse(line: &str) -> Option<Op> {
        let mut it = line.split_whitespace();
        let kind = it.next()?;
        let args: Vec<&str> = it.collect();

        // Exactly one `u8` argument, or refuse.
        let one = |args: &[&str]| -> Option<u8> {
            match args {
                [a] => a.parse::<u8>().ok(),
                _ => None,
            }
        };
        // Exactly two `u8` arguments, or refuse.
        let two = |args: &[&str]| -> Option<(u8, u8)> {
            match args {
                [a, b] => Some((a.parse::<u8>().ok()?, b.parse::<u8>().ok()?)),
                _ => None,
            }
        };
        // Exactly zero arguments, or refuse.
        let none = |args: &[&str]| -> Option<()> {
            if args.is_empty() {
                Some(())
            } else {
                None
            }
        };

        Some(match kind {
            "produce" => {
                let (i, n) = two(&args)?;
                Op::Produce(i, n)
            }
            "jump" => {
                let (i, j) = two(&args)?;
                Op::Jump(i, j)
            }
            "tamper" => {
                let (i, j) = two(&args)?;
                Op::Tamper(i, j)
            }
            "replay" => {
                let (i, j) = two(&args)?;
                Op::Replay(i, j)
            }
            "deliver" => Op::Deliver(one(&args)?),
            "burst" => Op::Burst(one(&args)?),
            "drop" => Op::Drop(one(&args)?),
            "restart" => Op::Restart(one(&args)?),
            "receive" => Op::Receive(one(&args)?),
            "spend" => Op::Spend(one(&args)?),
            "forget" => Op::Forget(one(&args)?),
            "forge-rows" => Op::ForgeRows(one(&args)?),
            "invalid" => Op::Invalid(one(&args)?),
            "drain" => {
                none(&args)?;
                Op::Drain
            }
            _ => return None,
        })
    }
}

/// Render a whole sequence as a `consensus_scenarios.txt` case — the permanent-coverage form.
pub fn as_case(name: &str, parties: usize, ops: &[Op]) -> String {
    let lines: Vec<String> = ops.iter().map(|op| op.to_case_line(parties)).collect();
    format!("name {name}\nparties {parties}\n{}\n", lines.join("\n"))
}

/// Render a sequence as the corpus wire form.
pub fn as_corpus(parties: usize, seed: u64, ops: &[Op]) -> String {
    let lines: Vec<String> = ops.iter().map(|op| op.to_corpus_line()).collect();
    format!("# parties {parties}\n# seed {seed}\n{}\n", lines.join("\n"))
}

/// Parse a corpus file back into `(parties, seed, ops)`.
///
/// Both headers are REQUIRED and every op line must parse: a corpus entry is a claim that this exact
/// schedule on this exact party count and seed was interesting, and a partially-understood file cannot
/// support that claim. `None` means "skip this file", never "replay what I could make out of it".
pub fn from_corpus(text: &str) -> Option<(usize, u64, Vec<Op>)> {
    let mut parties: Option<usize> = None;
    let mut seed: Option<u64> = None;
    let mut ops = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# parties ") {
            parties = Some(rest.trim().parse().ok()?);
            continue;
        }
        if let Some(rest) = line.strip_prefix("# seed ") {
            seed = Some(rest.trim().parse().ok()?);
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        ops.push(Op::parse(line)?);
    }
    Some((parties?, seed?, ops))
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::{as_corpus, from_corpus, Op};
    use crate::consensus_scenarios::Sim;

    /// ⛔ A TRUNCATED OP LINE IS REFUSED, NEVER RESCUED.
    ///
    /// The tolerant form of this parser turned `"jump 1"` into `Jump(1, 0)` — a DIFFERENT op naming a
    /// different pair of parties. Every consumer downstream (shrink predicate, regression replay,
    /// emitted reproducer) would then be reasoning about a schedule nobody recorded. Both halves are
    /// pinned: the malformed lines are refused, AND the well-formed ones still parse.
    #[test]
    fn a_truncated_op_line_is_refused_rather_than_rescued() {
        for bad in [
            "jump 1",            // two-argument op, one argument given
            "produce 0",         // two-argument op, one argument given
            "tamper",            // two-argument op, none given
            "replay 1",          // two-argument op, one argument given
            "deliver",           // one-argument op, none given
            "deliver 1 2",       // one-argument op, two given
            "drain 0",           // zero-argument op, one given
            "spend x",           // unparsable argument
            "spend 999",         // out of u8 range
            "teleport 1 2",      // unknown kind
        ] {
            assert!(
                Op::parse(bad).is_none(),
                "{bad:?} must be REFUSED — a rescued line replays a schedule that was never recorded"
            );
        }
        // MUST-STAY-GREEN: the well-formed forms still parse to exactly the op they name.
        assert_eq!(Op::parse("jump 1 2"), Some(Op::Jump(1, 2)));
        assert_eq!(Op::parse("produce 0 3"), Some(Op::Produce(0, 3)));
        assert_eq!(Op::parse("deliver 9"), Some(Op::Deliver(9)));
        assert_eq!(Op::parse("drain"), Some(Op::Drain));
        assert_eq!(Op::parse("forge-rows 1"), Some(Op::ForgeRows(1)));
    }

    /// A corpus file missing either header is skipped WHOLE — never replayed at a guessed party count.
    #[test]
    fn a_corpus_file_missing_a_header_is_skipped_whole() {
        assert!(from_corpus("# seed 7\nproduce 0 1\n").is_none(), "no party count ⇒ skip the file");
        assert!(from_corpus("# parties 2\nproduce 0 1\n").is_none(), "no seed ⇒ skip the file");
        assert!(from_corpus("# parties 2\n# seed 7\njump 1\n").is_none(), "a bad op line ⇒ skip the file");
        assert!(from_corpus("# parties 2\n# seed 7\nproduce 0 1\n").is_some(), "a complete file parses");
    }
}
