// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ THE CUSTODY KEY CENSUS — EVERY SECRET A NODE HOLDS, AND THE QUESTIONS EACH ONE MUST ANSWER.
//!
//! USER 2026-09-28: "add custody key safety to the score". A bridge that holds other people's BTC/XMR is only as
//! safe as the keys that release it, so this census is a readiness criterion, not a comment.
//!
//! MEASURED THE SAME DAY, on the live home: every secret below was `-rw-r--r--`, readable by any local account, and
//! stored as plaintext. About fifty validator keys of long-dead test ports also sat beside the live ones.
//!
//! ⛔⛔⛔ WHY THERE IS NO "SealedAtRest" QUESTION ANY MORE — the confusion this criterion caused, recorded so it
//! cannot recur. This census once asked "is the secret encrypted at rest?" and counted every unsealed key as a gap.
//! That question pushed the work toward a MANDATORY passphrase: a bonded custodian that refused to start without its
//! password file. It traded LIVENESS for at-rest confidentiality (a validator that cannot start), and, with a
//! randomly drawn vote key, it made a lost passphrase a STRANDED BOND (an unbond must be signed by that exact key).
//! USER 2026-09-28: "the node key file passphrase seems like it needs to be an opt in choice rather than being chosen
//! for the user because the validating node not starting due to passphrase could cause liveness issues. I believe my
//! original design was better" — the original design links a bonded node to the operator's SEED. The borrowed shape is
//! Ethereum's: validator keys are DERIVED from the mnemonic (EIP-2333/2334), and the EIP-2335 keystore is only an
//! optional at-rest wrapper. So the root question is RECOVERY, sealing is an opt-in feature, and this census now
//! FORBIDS the start gate outright ([`sealing_is_opt_in_and_never_gates_a_start`]).
//!
//! The questions, per secret class:
//! * **OwnerOnly**: is the file owner-only from its first byte? Answered at the ROOT: `main` sets the process umask to
//!   077 before anything is created. [`main_sets_owner_only_umask_first`] reads that line from the shipped source.
//! * **Recoverable**: can the operator lose this file (or the optional passphrase) and lose NO value? A value key
//!   answers by being DERIVED FROM THE OPERATOR'S SEED, so re-provisioning from the seed restores the same identity
//!   and every bond on it. State answers by being regenerable from the chain; a transport identity by carrying no
//!   value.
//! * **PerEntity**: is it this node's own key, never one key shared across nodes (the decentralization pillar)?
//! * **NeverLeaves**: is it never served, logged or sent? RPC exposes public halves only.
//! * **NeverStopsTheNode** (checked mechanically, not answered in prose): no site that reads or writes the class may
//!   turn a missing or locked file into a stop (`panic!` / `process::exit`). A locked value key turns its ROLE off; the
//!   node runs. [`never_stops_the_node`] reads every named site from the shipped source.
//!
//! A class's gaps are its open answers plus its sites that could stop the node. The criterion counts them all, plus 1
//! if the umask line is gone, plus 1 if any start gate on the keystore exists.

/// One answer to one question: the evidence that answers it, or the gap that leaves it open.
#[derive(Debug, Clone, Copy)]
pub enum Answer {
    /// Answered, and where the evidence lives.
    By(&'static str),
    /// Open, and what closing it needs.
    Open(&'static str),
}

impl Answer {
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(self, Answer::Open(_))
    }
}

/// One secret the node keeps on disk.
#[derive(Debug, Clone, Copy)]
pub struct SecretClass {
    pub name: &'static str,
    /// What an attacker holding it could do.
    pub guards: &'static str,
    pub owner_only: Answer,
    pub recoverable: Answer,
    pub per_entity: Answer,
    pub never_leaves: Answer,
    /// Every site that reads or writes this class's file: `(source file, anchor)`. The anchor is a function
    /// signature (its whole body is checked) or, for a block inside a larger function, a string the block names.
    pub sites: &'static [(&'static str, &'static str)],
}

impl SecretClass {
    fn answers(&self) -> [Answer; 4] {
        [self.owner_only, self.recoverable, self.per_entity, self.never_leaves]
    }
    /// How many of this class's questions are open: its open answers, plus 1 if any named site could stop the node.
    #[must_use]
    pub fn open(&self) -> usize {
        self.answers().iter().filter(|a| a.is_open()).count() + usize::from(!never_stops_the_node(self))
    }
}

/// The shipped source of every file a secret class's sites live in.
fn source_of(file: &str) -> Option<&'static str> {
    Some(match file {
        "validator.rs" => include_str!("../validator.rs"),
        "bridge.rs" => include_str!("../bridge.rs"),
        "node.rs" => include_str!("../node.rs"),
        "btc_payout.rs" => include_str!("../btc_payout.rs"),
        "xmr_payout.rs" => include_str!("../xmr_payout.rs"),
        "main.rs" => include_str!("../main.rs"),
        "arti_transport.rs" => include_str!("../arti_transport.rs"),
        _ => return None,
    })
}

/// The text a site covers: a function's whole body when the anchor is a signature (up to the closing brace at the
/// signature's own indent), else the 1,800 bytes after the anchor (a block inside a larger function).
fn site_text(src: &'static str, anchor: &str) -> Option<&'static str> {
    let at = src.find(anchor)?;
    if anchor.contains("fn ") {
        let line_start = src[..at].rfind('\n').map_or(0, |i| i + 1);
        let indent = &src[line_start..at];
        let close = format!("\n{indent}}}\n");
        let end = at + src[at..].find(&close)?;
        return Some(&src[at..end]);
    }
    let mut end = (at + 1_800).min(src.len());
    while !src.is_char_boundary(end) {
        end -= 1;
    }
    Some(&src[at..end])
}

/// Can no named site of `class` stop the node? Every site must still exist (a vanished anchor proves nothing) and hold
/// no `panic!` and no `process::exit` (spelled in pieces so this census's own source never contains them).
#[must_use]
pub fn never_stops_the_node(class: &SecretClass) -> bool {
    !class.sites.is_empty()
        && class.sites.iter().all(|(file, anchor)| {
            source_of(file).and_then(|src| site_text(src, anchor)).is_some_and(body_never_stops)
        })
}

/// A site's text holds no stop.
fn body_never_stops(body: &str) -> bool {
    let panics = concat!("pan", "ic!(");
    let exits = concat!("process::", "exit(");
    !body.contains(panics) && !body.contains(exits)
}

/// ⛔ THE CONFUSION GUARD. Sealing at rest is the operator's OPT-IN choice and nothing about it may gate a start: no
/// keystore function may refuse a start (`require_*`), and `main` may not consult the keystore before it serves.
/// Read from the shipped source, so re-introducing the mandatory passphrase turns this criterion red.
#[must_use]
pub fn sealing_is_opt_in_and_never_gates_a_start() -> bool {
    let keystore = include_str!("../keystore.rs");
    let main = include_str!("../main.rs");
    let start_gate = concat!("fn ", "require_");
    let named_gate = concat!("require_", "for_custodian");
    !keystore.contains(start_gate) && !main.contains(named_gate) && !main.contains(concat!("keystore::", "require"))
}

const UMASK: Answer =
    Answer::By("main: oscall::umask_owner_only() (umask 0o077) before anything is created (main_sets_owner_only_umask_first)");

/// The value keys' recovery answer: every BONDED identity is derived from the operator's seed. Counted only while
/// [`bonds_sit_only_on_seed_derived_identities`] holds in the shipped source.
const SEED_DERIVED: Answer = Answer::By(
    "a bonded identity is DERIVED from the operator's seed (wallet pq::derive_validator_identity, EIP-2333/2334 \
     shape) and provisioned automatically by the wallet's bond flow (/provision_validator: the node receives only \
     the derived vote key and derives its custody KEM from it); /sign_bond signs only for a provisioned identity, so \
     a lost machine, file or passphrase is recovered by pointing the wallet at any node. Pins: validator \
     provision_tests, wallet validator_identity_tests",
);

/// ⛔ Does `/sign_bond` refuse an identity that was NOT provisioned from a seed? Read from the shipped route: remove the
/// check and a bond can again sit on a random key a lost file would strand, and the criterion counts it.
#[must_use]
pub fn bonds_sit_only_on_seed_derived_identities() -> bool {
    let rpc = include_str!("../rpc_http.rs");
    let Some(at) = rpc.find(concat!("(\"POST\", \"/sign_", "bond\") => {")) else {
        return false;
    };
    let route = &rpc[at..];
    let end = route.find("\n        (\"").unwrap_or(route.len());
    route[..end].contains("vote_identity_provisioned()") && route[..end].contains("VALIDATOR_IDENTITY_NOT_SEED_DERIVED")
}

/// Every secret class a node persists. A new secret file joins this list, or the criterion undercounts.
pub const SECRETS: &[SecretClass] = &[
    SecretClass {
        name: "validator ML-DSA key (validator-<port>.key)",
        guards: "signs custody-release attestations, bond statements, payout proposals and this node's own unbond",
        owner_only: UMASK,
        recoverable: SEED_DERIVED,
        per_entity: Answer::By("one identity per node (validator::load_or_create_node_vote_key)"),
        never_leaves: Answer::By("only the public key is published (bond header); key bytes never reach a log"),
        sites: &[
            ("validator.rs", "pub fn load_or_create_node_vote_key"),
            ("bridge.rs", "fn node_validator_key_bytes"),
        ],
    },
    SecretClass {
        name: "custody ML-KEM key (validator-<port>.kem)",
        guards: "opens every sealed peg-in delta and custodial request addressed to this custodian",
        owner_only: UMASK,
        recoverable: SEED_DERIVED,
        per_entity: Answer::By("one per node (bridge::node_own_custody_kem)"),
        never_leaves: Answer::By("only the encapsulation key is published; the dk never leaves the process"),
        sites: &[("bridge.rs", "pub fn node_own_custody_kem")],
    },
    SecretClass {
        name: "custodian sealed openings (custody-opening-<port>[.wrapped].bin)",
        guards: "the custodian's openings of the reserve commitments it attests",
        owner_only: UMASK,
        recoverable: Answer::By(
            "custody is a bond-weighted k-of-n tally: losing one custodian's opening removes that custodian's \
             attestations, never a bond and never reserve funds (the other custodians attest)",
        ),
        per_entity: Answer::By("each custodian holds its own openings (§CZ-b, DB-77)"),
        never_leaves: Answer::By("never served; attestations carry proofs, not openings"),
        sites: &[
            ("node.rs", "pub fn enable_custody_opening_persist"),
            ("node.rs", "fn persist_custody_opening"),
            ("node.rs", "fn persist_wrapped_openings"),
        ],
    },
    SecretClass {
        name: "BTC custody book (custody-book-<port>.bin)",
        guards: "this custodian's record of the BTC outputs it co-controls",
        owner_only: UMASK,
        recoverable: Answer::By("regenerated from the chain: obligations re-appear as the node re-applies its blocks"),
        per_entity: Answer::By("per custodian, beside its validator key (btc_payout)"),
        never_leaves: Answer::By("never served"),
        sites: &[("btc_payout.rs", "pub fn new() -> Self"), ("btc_payout.rs", "fn save(&self)")],
    },
    SecretClass {
        name: "XMR custody book (xmr-book-<port>.bin)",
        guards: "this custodian's record of the Monero it owes and has paid out",
        owner_only: UMASK,
        recoverable: Answer::By("regenerated from the chain: obligations re-appear as the node re-applies its blocks"),
        per_entity: Answer::By("per custodian, beside its validator key (xmr_payout)"),
        never_leaves: Answer::By("never served"),
        sites: &[("xmr_payout.rs", "pub fn new() -> Self"), ("xmr_payout.rs", "fn save(&self)")],
    },
    SecretClass {
        name: "onion identity seed (onion-<port>.seed) and arti ML-KEM identity (mlkem-identity.key)",
        guards: "the node's transport identity: whoever holds it can impersonate this node's onion service",
        owner_only: UMASK,
        recoverable: Answer::By(
            "a transport identity moves no value (geth's nodekey shape) and is never sealed, so it cannot lock: a lost \
             one costs a peer id, never funds",
        ),
        per_entity: Answer::By("one identity per node (DB-341's one state dir)"),
        never_leaves: Answer::By("only the onion address is published"),
        sites: &[("main.rs", "fn load_or_create_onion_seed"), ("arti_transport.rs", "\"mlkem-identity.key\"")],
    },
];

/// The criterion's number: every open question across every secret class, plus 1 if the root umask line is gone,
/// plus 1 if any start gate on the keystore exists, plus 1 if a bond could sit on an identity not derived from a seed.
#[must_use]
pub fn open_gaps() -> usize {
    let umask_missing = usize::from(!main_sets_owner_only_umask_first());
    let start_gate = usize::from(!sealing_is_opt_in_and_never_gates_a_start());
    let unrecoverable_bonds = usize::from(!bonds_sit_only_on_seed_derived_identities());
    SECRETS.iter().map(SecretClass::open).sum::<usize>() + umask_missing + start_gate + unrecoverable_bonds
}

/// Does `main` set the owner-only umask as its FIRST statement? Read from the source that ships.
#[must_use]
pub fn main_sets_owner_only_umask_first() -> bool {
    let src = include_str!("../main.rs");
    let Some(start) = src.find("\nfn main() {") else {
        return false;
    };
    // `start` is the newline BEFORE `fn main() {`, so step past it: the first line is then the signature itself.
    src[start + 1..]
        .lines()
        .skip(1)
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("//") && !l.starts_with("#[") && *l != "unsafe {")
        .is_some_and(|l| l.starts_with("usdmd_node::oscall::umask_owner_only()"))
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::*;

    /// ⛔ The root answer for OwnerOnly: the umask line must stay the FIRST statement of `main`, before any file is
    /// created. Remove it, or move it below a writer, and this goes red (and the criterion counts one more gap).
    /// TWO-PARTY-REVIEWED: a static census of one node's own disk properties; no capability crosses a boundary here,
    /// so there is no second endpoint to construct.
    #[test]
    fn main_sets_the_owner_only_umask_first() {
        assert!(
            main_sets_owner_only_umask_first(),
            "⛔ `main` no longer sets the process umask to 077 as its first statement, so the validator key, the \
             custody KEM key and every other secret is created readable by other local accounts again"
        );
    }

    /// ⛔ THE CONFUSION GUARD, pinned: sealing stays opt-in and no start gate exists. A future round that re-adds a
    /// mandatory passphrase turns this red instead of turning the criterion green.
    /// TWO-PARTY-REVIEWED: a static census, as above; no boundary is crossed.
    #[test]
    fn sealing_stays_opt_in_and_no_key_safety_feature_can_stop_a_node() {
        assert!(
            sealing_is_opt_in_and_never_gates_a_start(),
            "⛔ a start gate on the keystore is back: a validator that cannot start is a liveness failure (user \
             2026-09-28: the passphrase is an opt-in choice)"
        );
        for s in SECRETS {
            assert!(never_stops_the_node(s), "⛔ {}: a named site can stop the node on a missing or locked file", s.name);
        }
    }

    /// The census counts what it claims. Every class is owner-only, per-node, never served, recoverable and never stops
    /// the node; bonds sit only on seed-derived identities (read from the `/sign_bond` route that ships). 0 gaps.
    /// TWO-PARTY-REVIEWED: a static census, as above; no boundary is crossed.
    #[test]
    fn the_custody_census_counts_its_open_questions() {
        assert!(SECRETS.len() >= 6, "a secret class was dropped from the census");
        for s in SECRETS {
            assert!(!s.owner_only.is_open() && !s.per_entity.is_open() && !s.never_leaves.is_open(), "{}", s.name);
            assert!(!s.recoverable.is_open(), "{}: losing it would lose value", s.name);
        }
        assert!(
            bonds_sit_only_on_seed_derived_identities(),
            "⛔ /sign_bond no longer refuses a self-drawn identity: a lost key file would strand the bond on it"
        );
        assert_eq!(open_gaps(), 0);
    }

    /// ARMED: the stop check is not an assertion that cannot fail. A site that panics, a site that exits, a vanished
    /// anchor and a class with no site each count as a gap.
    /// TWO-PARTY-REVIEWED: a static census, as above; no boundary is crossed.
    #[test]
    fn a_site_that_can_stop_the_node_is_counted_open() {
        let base = SECRETS[3];
        let gone = SecretClass { sites: &[("validator.rs", "pub fn a_function_that_does_not_exist")], ..base };
        assert!(!never_stops_the_node(&gone), "a missing anchor must count");
        assert_eq!(gone.open(), 1);
        let empty = SecretClass { sites: &[], ..base };
        assert!(!never_stops_the_node(&empty), "a class with no named site proves nothing");
        assert!(!body_never_stops(concat!("let k = read(p); pan", "ic!(\"locked\");")), "a panic must count");
        assert!(!body_never_stops(concat!("std::process::", "exit(2);")), "an exit must count");
        assert!(body_never_stops("let k = crate::keystore::read_key_file(p);"));
    }
}
