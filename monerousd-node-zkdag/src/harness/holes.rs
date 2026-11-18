// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ THE ONE-SWEEP HOLE SCANNER — every census in the tree, every open hole, by NAME, in one cheap run.
//!
//! User 2026-10-03, verbatim: *"the goal is to be able to close all readiness wholes quickly in one swoop so obviously our
//! cheap census must contain the entire ecosystem. The entire ecosystem must be able to be checked quickly and ceaply for
//! holes because doing it one by one is whats causing blind spots … The tool should print all of the holes found and then
//! we can fix them"*.
//!
//! WHY. The readiness report counts holes, and each census lives in its own module with its own test. Every hole found this
//! week came from a one-off hunt (DB-368, DB-369, DB-370, DB-371, DB-372, the unrecorded register). A hole nobody hunted
//! stayed invisible, and a count never says WHICH hole to fix.
//!
//! WHAT. [`every_hole`] walks every census and returns each open item with its category, name and what is missing:
//! - value creation (open sites, the census universe, filed-open, destruction without authority);
//! - privacy (open surfaces, the census universe, filed-open);
//! - custody (open secret classes and the process-level checks);
//! - value classes (Unproven, in-process only, real-node rows whose LATEST recorded run is not a PASS, rows standing on a
//!   backfilled pass);
//! - silent fund loss (filed);
//! - the rogue-role census (open cells);
//! - the known-red pins (`scratchpad/known-reds.txt`);
//! - the live readiness criteria not met.
//!
//! Each census derives its universe from code, so a new class, field or site appears here with no edit.
//! The decider's own censuses (degree, free-witness) run in their crate: `scratchpad/holes.sh` runs both and prints one
//! list.
//!
//! RUN IT FIRST every round. The printed list IS the work list.

use crate::harness::{adversary_census, custody, e2e_claims, fund_loss, privacy, readiness, rogue_census, value_creation};

use crate::harness::surface_census::{BLIND, EXPLOIT, UNMEASURED};

/// One open hole: its TIER (impact if real — T0 funds, T1 privacy, T2 keys & PQ, T3 liveness, T4 function; an unknown
/// impact takes T0) and its KIND (EXPLOIT measured, BLIND SPOT uncovered, UNMEASURED claimed without a recorded pass).
#[derive(Debug, Clone)]
pub struct Hole {
    pub tier: u8,
    pub kind: &'static str,
    pub category: &'static str,
    pub name: String,
    pub detail: String,
}

/// The tier and kind of every census category. A category not in this table takes T0 BLIND SPOT: the no-assumption rule.
fn classify(category: &str) -> (u8, &'static str) {
    match category {
        "value-creation site" | "value-creation filed open" | "silent fund loss filed" => (0, EXPLOIT),
        "value-creation census universe" | "rogue-role census open cell" | "rogue-role census coverage"
        | "value destruction: transition not pinned" => (0, BLIND),
        "value class real-node run NOT PASSING" | "known-red pin" => (0, EXPLOIT),
        "value class UNPROVEN" | "value class proven IN PROCESS ONLY" | "value class awaiting a recorded re-run" | "readiness criterion not met" => (0, UNMEASURED),
        "fixture calibration red (not a chain verdict)" => (3, UNMEASURED),
        // THE SIMULATOR (user 2026-10-06): a failing journey step or a changed field is a measured red; a step with no arm, or a
        // record older than the source, is unmeasured; a boot step outside `Node::boot` is drift the simulator cannot see.
        "simulated journey step FAILED" | "state changed by a production restart" => (0, EXPLOIT),
        // DB-402: two nodes on the same chain holding different replicated state (R1), or a conversion that throws away a
        // field its source carries (R3) — each is DB-401's class: one node standing on local truth.
        "replicated state not one function of the chain" | "conversion drops a carried field" => (0, EXPLOIT),
        "simulated journey step has no arm" | "simulator record is stale" => (0, UNMEASURED),
        "boot step outside Node::boot" => (0, BLIND),
        "surface the simulator never exercised" => (0, BLIND),
        "simulator coverage not yet re-run on this source" => (0, UNMEASURED),
        "simulated route sweep RED" => (0, EXPLOIT),
        "privacy surface" | "privacy filed open" => (1, EXPLOIT),
        "privacy census universe" => (1, BLIND),
        "custody secret" => (2, BLIND),
        "custody process" => (2, EXPLOIT),
        // the adversary census (user 2026-10-04): an unsimulated adversary is a T0 hole; a measured red is a T0 exploit
        "adversary network scenario open" | "adversary economic scenario open" | "crypto parameter unmeasured" => (0, UNMEASURED),
        "adversary network scenario RED" | "adversary economic scenario RED" | "crypto parameter below bound" | "circuit statement RED" => (0, EXPLOIT),
        "circuit statement unwritten" => (1, UNMEASURED),
        "adversary census coverage" => (0, BLIND),
        "app makes a clearnet / third-party request" | "launchpad tile loads over clearnet (no served site)" => (1, EXPLOIT),
        "app uses classical (pre-quantum) crypto" | "app writes a secret to browser storage" => (2, EXPLOIT),
        "app calls a node route that does not exist"
        | "app calls a wallet bridge method the wallet does not implement"
        | "wallet front end invokes a command the Rust core does not define"
        | "launchpad tile names a site the node does not serve" => (4, EXPLOIT),
        _ => (0, BLIND),
    }
}

fn hole(category: &'static str, name: impl Into<String>, detail: impl Into<String>) -> Hole {
    let (tier, kind) = classify(category);
    Hole { tier, kind, category, name: name.into(), detail: detail.into() }
}

pub const TIER_NAMES: [&str; 5] = [
    "T0 FUNDS — value created, destroyed, stolen or locked; soundness",
    "T1 PRIVACY — value, identity, linkage, amount or metadata revealed",
    "T2 KEYS & PQ — a key exposed, or pre-quantum crypto",
    "T3 LIVENESS — halt, crash, exhaustion, unbounded growth",
    "T4 FUNCTION — a feature a user relies on is dead or unproven",
];

/// Every open hole every in-process census knows of, in a fixed category order.
#[must_use]
pub fn every_hole() -> Vec<Hole> {
    let mut h = Vec::new();

    // ── 1. VALUE CREATION: can value be created without authority, in the wrong amount, twice, or locally?
    for s in value_creation::SITES.iter().filter(|s| !s.is_closed()) {
        h.push(hole("value-creation site", s.name, s.gaps().join("; ")));
    }
    for g in value_creation::census_universe_gaps() {
        h.push(hole("value-creation census universe", g, "a minting function or class outside the census"));
    }
    for f in value_creation::FILED_OPEN {
        h.push(hole("value-creation filed open", *f, ""));
    }
    // destruction: the transitions here; every class's `burn` cell rides the rogue-role census (section 6)
    for (site, cell) in value_creation::DESTRUCTION_BY_TRANSITION {
        if let rogue_census::Cell::Open(why) = cell {
            h.push(hole("value destruction: transition not pinned", *site, *why));
        }
    }

    // ── 2. PRIVACY: does viewing the chain leak content, shape, linkage or ordering?
    for s in privacy::SURFACES.iter().filter(|s| !s.is_closed()) {
        h.push(hole("privacy surface", s.name, s.gaps().join("; ")));
    }
    for g in privacy::census_universe_gaps() {
        h.push(hole("privacy census universe", g, "a public field or door outside the census"));
    }
    for f in privacy::FILED_OPEN {
        h.push(hole("privacy filed open", *f, ""));
    }

    // ── 3. CUSTODY: every secret a node holds, four questions each.
    for c in custody::SECRETS.iter().filter(|c| c.open() > 0) {
        h.push(hole("custody secret", c.name, format!("{} unanswered question(s); guards: {}", c.open(), c.guards)));
    }
    if !custody::main_sets_owner_only_umask_first() {
        h.push(hole("custody process", "umask", "main does not set the owner-only umask first"));
    }
    if !custody::sealing_is_opt_in_and_never_gates_a_start() {
        h.push(hole("custody process", "sealing", "sealing gates a node start"));
    }
    if !custody::bonds_sit_only_on_seed_derived_identities() {
        h.push(hole("custody process", "bond identity", "a bond can sit on an identity no seed restores"));
    }

    // ── 4. VALUE CLASSES: can a user move every kind of value, proven on real nodes?
    let passed = e2e_claims::real_node_pins_whose_latest_run_passed();
    let backfilled = e2e_claims::real_node_pins_counting_on_backfill();
    for (class, m) in e2e_claims::VALUE_CLASSES {
        match m {
            e2e_claims::Moved::Unproven(why) => h.push(hole("value class UNPROVEN", *class, *why)),
            e2e_claims::Moved::CrossNode(pin) => {
                h.push(hole("value class proven IN PROCESS ONLY", *class, format!("no real-node journey; pin {pin}")))
            }
            e2e_claims::Moved::RealNodes(pin) if !passed(pin) => {
                h.push(hole("value class real-node run NOT PASSING", *class, format!("latest recorded run of {pin} is not a PASS")))
            }
            e2e_claims::Moved::RealNodes(pin) if backfilled.iter().any(|b| b == pin) => h.push(hole(
                "value class awaiting a recorded re-run",
                *class,
                format!("{pin} counts on a BACKFILLED pass; re-run it"),
            )),
            _ => {}
        }
    }

    // ── 5. SILENT FUND LOSS (filed).
    for (site, why) in fund_loss::FILED_SILENT {
        h.push(hole("silent fund loss filed", *site, *why));
    }

    // ── 6. ROGUE-ROLE CENSUS: class × attack cells not yet pinned.
    for (class, attack, why) in rogue_census::open_cells() {
        h.push(hole("rogue-role census open cell", format!("{class} × {attack}"), why));
    }
    for g in rogue_census::coverage_gaps() {
        h.push(hole("rogue-role census coverage", g, "a class × attack with no cell"));
    }

    // ── 6b. ADVERSARY CENSUS (user 2026-10-04): the adversaries no surface census measures — network, economic, crypto
    //        parameters, circuit statements — each a simulated event with a recorded pin, or a hole.
    for s in adversary_census::SCENARIOS {
        match s.verdict {
            adversary_census::Verdict::Open(why) => h.push(hole(
                adversary_census::open_category(s.family),
                format!("{} × {}", s.family, s.name),
                format!("{why} — defense claimed: {}", s.defense),
            )),
            adversary_census::Verdict::Red(pin, mech) => {
                h.push(hole(adversary_census::red_category(s.family), format!("{} × {}", s.family, s.name), format!("{pin}: {mech}")))
            }
            adversary_census::Verdict::Pinned(_) | adversary_census::Verdict::Bound(_) => {}
        }
    }
    for g in adversary_census::coverage_gaps() {
        h.push(hole("adversary census coverage", g, "a family with no row, a pin that exists nowhere, or an unfiled red"));
    }

    // ── 7. KNOWN-RED PINS (each is a red the tree carries).
    let known = std::fs::read_to_string(crate::harness::scratchpad_dir().join("known-reds.txt")).ok();
    // A line `FIXTURE <pin>` is a red the file's own comment attributes to the FIXTURE (a calibration or precondition that
    // did not hold in the harness), never to the chain — user 2026-09-17: "a fixture red is not a chain verdict". It is
    // still listed (unmeasured, never hidden), in its own class, so the H8 row counts chain verdicts only.
    for line in known.as_deref().map(str::lines).into_iter().flatten().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        match line.strip_prefix("FIXTURE ") {
            Some(pin) => h.push(hole("fixture calibration red (not a chain verdict)", pin.trim(), "RED in the harness by its own fixture's calibration; listed in scratchpad/known-reds.txt as FIXTURE — re-run or re-state the fixture, the chain is not judged by it")),
            None => h.push(hole("known-red pin", line, "RED in the tree; listed in scratchpad/known-reds.txt")),
        }
    }

    // ── 8. THE WALLET AND EVERY LAUNCHPAD APP (user 2026-10-03: the ecosystem includes the launchpad apps).
    for (category, at, what) in crate::harness::app_census::app_holes() {
        if category != "app census coverage" {
            h.push(hole(category, at, what));
        }
    }

    // ── 8b. EVERY SURFACE OF THE ECOSYSTEM (the zero-blind-spot layer): routes, peer messages, wallet commands, the dapp
    //        bridge, decodes, disk writes, logs, unsafe code, dependencies, primitives, files, and every CLOSED census
    //        row's measurement.
    let (surface, _) = crate::harness::surface_census::surface_holes();
    let driven = adversary_driven_routes();
    let doors = fuzz_driven_decode_doors();
    for s in surface {
        if s.category == "node route with no adversarial test" {
            let (m, p) = s.name.split_once(' ').unwrap_or(("ANY", s.name.as_str()));
            if driven.iter().any(|(dm, dp)| crate::harness::sim_coverage::route_covers(dm, dp, m, p)) {
                continue; // the adversarial route harness drove it on the current source (B1 (i), 2026-10-22)
            }
        }
        if s.category == "decode of outside bytes no fuzzer reaches" && doors.iter().any(|d| s.detail.contains(&format!("door `{d}`"))) {
            continue; // the decode-door replay drove its door green on the current source (B1 (ii), 2026-10-22)
        }
        h.push(Hole { tier: s.tier, kind: s.kind, category: s.category, name: s.name, detail: s.detail });
    }

    // ── 8c. THE CIRCUIT SWEEP (written by scratchpad/holes.sh from a strict-mode decider run). Absent or older than the
    //        decider's newest source ⇒ the circuit half is UNMEASURED, never silently green.
    h.extend(circuit_holes());

    // ── 8d. THE SIMULATOR — the full node journey and the restart census, and whether either is stale.
    h.extend(simulator_holes());

    // ── 9. LIVE READINESS CRITERIA NOT MET (the register's own rows that need no run).
    for c in readiness::live_criteria() {
        let met = if c.ceiling { c.current <= c.target } else { c.current >= c.target };
        if !met {
            h.push(hole("readiness criterion not met", c.name, format!("{} / {} — {}", c.current, c.target, c.blocker)));
        }
    }
    h.sort_by(|a, b| (a.tier, a.kind, a.category, &a.name).cmp(&(b.tier, b.kind, b.category, &b.name)));
    h
}

/// The categories whose holes are FAILING TESTS (a measured red), as opposed to surfaces no test measures.
pub const RED_CATEGORIES: [&str; 13] = [
    "crypto parameter below bound",
    "simulated journey step FAILED",
    "simulated route sweep RED",
    "state changed by a production restart",
    "replicated state not one function of the chain",
    "conversion drops a carried field",
    "known-red pin",
    "pin RED in its latest recorded run",
    "value class real-node run NOT PASSING",
    "adversary network scenario RED",
    "adversary economic scenario RED",
    "circuit statement RED",
    "fixture calibration red (not a chain verdict)",
];

/// MEASUREMENT DEBT (user 2026-10-27 "the watch … never counts unrun tests as holes"): a hole whose ONLY cause is a measurement not
/// yet made on this source — a simulator record older than the newest source, a coverage ledger with no run on the current source, a
/// listed red never run or whose latest recorded run passed, a value class waiting for its recorded re-run, a strict sweep older
/// than the decider. It is listed and counted APART from the tier holes: clear_debt.sh, the post-landing watch and the CPU farm make
/// the measurement at zero tokens, and the readiness verdict (R1) still requires ZERO debt as well as zero holes — the gate is as
/// strict as before; only the accounting is honest. MEASURED why, 2026-10-26 (scratchpad/holes-history.tsv): the total swung
/// 1118 ↔ 1402 between consecutive scans with every exploit count unchanged, because each landing staled the fast journey's coverage
/// record and +282 "surface the simulator never exercised" rows appeared until it re-ran — a burn-down no link could read.
pub const DEBT_CATEGORIES: [&str; 6] = [
    "red pin no longer in the tree",
    "simulator record is stale",
    "simulator coverage not yet re-run on this source",
    "value class awaiting a recorded re-run",
    "circuit sweep is stale",
    "circuit sweep never ran",
];
/// The red categories that are LISTINGS (a line in known-reds.txt), whose hole is debt when no failure is recorded for the listed
/// test or its latest recorded run passed. A measured red (a journey step that printed FAIL, a census that printed DIFFERS) is never
/// debt, whatever its cause index says: the row itself is the measurement.
const LISTING_CATEGORIES: [&str; 2] = ["known-red pin", "fixture calibration red (not a chain verdict)"];

#[must_use]
pub fn is_measurement_debt_with(
    h: &Hole,
    fails: &std::collections::HashMap<String, (String, String, String)>,
    latest: &std::collections::HashMap<String, (String, bool)>,
) -> bool {
    if DEBT_CATEGORIES.contains(&h.category) {
        return true;
    }
    if LISTING_CATEGORIES.contains(&h.category) {
        return matches!(cause_with(h, fails, latest), RedCause::NeverRecorded | RedCause::LatestRunPassed { .. })
            || is_instrument_red(h, fails, latest);
    }
    // a red whose latest recorded run PASSED is a stale listing, not a standing red (the pin ledger's newest-row rule)
    (RED_CATEGORIES.contains(&h.category) && matches!(cause_with(h, fails, latest), RedCause::LatestRunPassed { .. }))
        || is_instrument_red(h, fails, latest)
}

/// THE INSTRUMENT CLASS (user 2026-11-03: "measurement debt [is not] counted as holes until theres a proven funds loss hole").
/// A red whose recorded cause is the INSTRUMENT — the binary it drives was never built or is older than the source, its fixture's
/// calibration or precondition did not hold, it ran inconclusive, its own vacuity check fired, a perf canary with no baseline, a
/// stale ledger — measured nothing about the chain: it is a measurement not yet made, never a funds verdict. A journey step's own
/// FAIL detail is read the same way (a step that says "the real wallet binary is not built" judged no chain state). MEASURED
/// 2026-11-03 (holes-20261103-033720.log): 45 of the 136 exploit rows were this class, every one naming its absent instrument.
#[must_use]
pub fn is_instrument_cause(message: &str) -> bool {
    const MARKS: [&str; 15] = [
        "STALE BINARY",
        "binary is not built",
        "is not built at",
        "COULD NOT RAISE A REAL",
        "COULD NOT BE CREATED",
        "CALIBRATION",
        "calibration:",
        "PRECONDITION",
        "INCONCLUSIVE",
        "setup:",
        "vacuous",
        "SILENTLY WEAKENED",
        "PERF CANARY",
        "⛔ STALE:",
        "RED baseline",
    ];
    MARKS.iter().any(|m| message.contains(m))
}

fn is_instrument_red(
    h: &Hole,
    fails: &std::collections::HashMap<String, (String, String, String)>,
    latest: &std::collections::HashMap<String, (String, bool)>,
) -> bool {
    if !RED_CATEGORIES.contains(&h.category) {
        return false;
    }
    if h.category == "simulated journey step FAILED" && is_instrument_cause(&h.detail) {
        return true;
    }
    matches!(cause_with(h, fails, latest), RedCause::Panicked { message, .. } if is_instrument_cause(&message))
}

/// Every hole split into (the holes, the measurement debt).
#[must_use]
pub fn split_debt(holes: Vec<Hole>) -> (Vec<Hole>, Vec<Hole>) {
    let (fails, latest) = red_cause_index();
    holes.into_iter().partition(|h| !is_measurement_debt_with(h, &fails, &latest))
}

/// WHY a red is red (user 2026-10-06: "it shouldve stated the cause of the bugs not simply that holes exist").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedCause {
    /// The newest recorded failure: the panic site (file:line) and its message, from `scratchpad/red-causes.tsv`.
    Panicked { site: String, message: String, at: String },
    /// The test's LATEST ledger verdict is a pass, newer than its newest recorded failure: the listing is stale.
    LatestRunPassed { at: String },
    /// No failure of this test is recorded anywhere: the red was never measured with its cause (re-run it).
    NeverRecorded,
}

/// The short name (last `::` segment) of every test named in `text`.
fn test_names_in(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
        .map(|w| w.trim_matches(':')) // a census row's "pin_name: mechanism" (measured 2026-11-03: the WHIR row never matched its pin)
        .filter(|w| w.len() > 12 && w.contains('_'))
        .map(|w| w.rsplit("::").next().unwrap_or(w).to_string())
        .collect()
}

/// The newest recorded failure and the newest verdict of every test (by short name), read from the two ledgers.
fn red_cause_index() -> (std::collections::HashMap<String, (String, String, String)>, std::collections::HashMap<String, (String, bool)>) {
    let dir = crate::harness::scratchpad_dir();
    let mut fails = std::collections::HashMap::new();
    for line in std::fs::read_to_string(dir.join("red-causes.tsv")).unwrap_or_default().lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 5 {
            continue;
        }
        let short = f[2].rsplit("::").next().unwrap_or(f[2]).to_string();
        let newer = fails.get(&short).map_or(true, |(_, _, at): &(String, String, String)| f[0] >= at.as_str());
        if newer {
            fails.insert(short, (f[3].to_string(), f[4].to_string(), f[0].to_string()));
        }
    }
    // THE ONE LEDGER READER (surface_census::pin_ledger, lane d 2026-10-27): the same rows, the same branch rule and the same
    // "newest by timestamp" as the red-pin listing, so a listing and its cause can never disagree about a test's latest run.
    let latest: std::collections::HashMap<String, (String, bool)> = crate::harness::surface_census::pin_ledger_by_short_name()
        .into_iter()
        .map(|(short, row)| {
            let ok = row.ok();
            (short, (row.ts, ok))
        })
        .collect();
    (fails, latest)
}

/// The cause of one red hole: its newest recorded panic, unless a later recorded run passed.
#[must_use]
pub fn cause_of(h: &Hole) -> RedCause {
    let (fails, latest) = red_cause_index();
    cause_with(h, &fails, &latest)
}

fn cause_with(
    h: &Hole,
    fails: &std::collections::HashMap<String, (String, String, String)>,
    latest: &std::collections::HashMap<String, (String, bool)>,
) -> RedCause {
    let names = test_names_in(&format!("{} {}", h.name, h.detail));
    for n in &names {
        let fail = fails.get(n);
        if let Some((at, true)) = latest.get(n) {
            if fail.map_or(true, |(_, _, fat)| at > fat) {
                return RedCause::LatestRunPassed { at: at.clone() };
            }
        }
        if let Some((site, message, at)) = fail {
            // A LATER red whose cause was not captured must not inherit an older failure's cause (measured 2026-10-06: the
            // sweep's own 00:13 red was attributed to a panic recorded the day before, already fixed).
            if let Some((lat, false)) = latest.get(n) {
                if lat.as_str() > at.as_str() && !same_run(lat, at) {
                    return RedCause::NeverRecorded;
                }
            }
            return RedCause::Panicked { site: site.clone(), message: message.clone(), at: at.clone() };
        }
    }
    RedCause::NeverRecorded
}

/// Two ledger timestamps (ISO, second precision) from the same run: the cause and the verdict are written seconds apart.
fn same_run(a: &str, b: &str) -> bool {
    let secs = |t: &str| -> Option<i64> {
        let (d, h) = t.split_once('T')?;
        let dn: i64 = d.replace('-', "").parse().ok()?;
        let p: Vec<i64> = h.split(':').filter_map(|x| x.parse().ok()).collect();
        (p.len() == 3).then(|| dn * 86_400 + p[0] * 3600 + p[1] * 60 + p[2])
    };
    matches!((secs(a), secs(b)), (Some(x), Some(y)) if (x - y).abs() <= 600)
}

/// A FAMILY of causes that is one cause whatever line it fires on: the environment a journey needs was absent, or the
/// test ran out of its wall budget. Everything else is its own cause, keyed by site and message.
#[must_use]
pub fn cause_family(message: &str) -> Option<&'static str> {
    if message.contains("STALE BINARY") || message.contains("binary is not built") || message.contains("COULD NOT RAISE A REAL")
        || message.contains("COULD NOT BE CREATED")
    {
        return Some("ENVIRONMENT — a real-process journey's daemon/wallet binary was absent or older than the source (not a chain verdict; these run only after the full-journey simulator passes)");
    }
    if message.contains("DEADLINE BLOWN") || message.contains("deadline") && message.contains("budget") {
        return Some("TOO SLOW — the scenario ran out of its wall-clock budget (a slow test is the bug: its cost must be cut, not its budget raised)");
    }
    if is_instrument_cause(message) {
        return Some("INSTRUMENT — the fixture's calibration, precondition or own check did not hold (not a chain verdict)");
    }
    None
}

/// One ROOT CAUSE and the reds it explains: same panic site and same message stem (digits folded, first 90 chars).
#[derive(Debug, Clone)]
pub struct CauseGroup {
    pub signature: String,
    pub reds: Vec<String>,
}

/// Every red hole grouped by its cause, the largest group first. The non-red holes are surfaces no test measures; their
/// cause is their category (the missing instrument), counted separately by the printer.
#[must_use]
pub fn cause_groups(holes: &[Hole]) -> Vec<CauseGroup> {
    let (fails, latest) = red_cause_index();
    let mut groups: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for h in holes.iter().filter(|h| RED_CATEGORIES.contains(&h.category)) {
        let sig = match cause_with(h, &fails, &latest) {
            RedCause::Panicked { site, message, .. } => match cause_family(&message) {
                Some(f) => f.to_string(),
                None => {
                    let stem: String = message.chars().map(|c| if c.is_ascii_digit() { '#' } else { c }).take(90).collect();
                    format!("{site} — {stem}")
                }
            },
            RedCause::LatestRunPassed { .. } => "STALE LISTING — the latest recorded run PASSED (re-confirm and remove the listing)".to_string(),
            // A listing with no recorded run is MEASUREMENT DEBT and never reaches this grouping (is_measurement_debt_with), so a
            // NeverRecorded red here IS a recorded verdict — a census DIFFERS row, a FAILED row — whose panic site red-causes.tsv does
            // not hold (MEASURED 2026-10-27: 98 of 105 such rows were DB-402 replica-census fields, every one a measured divergence).
            RedCause::NeverRecorded => "CAUSE NOT CAPTURED — a recorded red (census DIFFERS / FAILED row) with no panic site in red-causes.tsv: read its log".to_string(),
        };
        groups.entry(sig).or_default().push(h.name.chars().take(140).collect());
    }
    let mut out: Vec<CauseGroup> = groups.into_iter().map(|(signature, reds)| CauseGroup { signature, reds }).collect();
    out.sort_by(|a, b| b.reds.len().cmp(&a.reds.len()).then(a.signature.cmp(&b.signature)));
    out
}

/// THE SIMULATOR'S HOLES (user 2026-10-06: "finish the ecosystem wide simulator … add checks to make sure its not stale so
/// it auto stays up to date"). Read from the records the simulator's own tests write:
/// - `scratchpad/sim-journey.tsv`: the LATEST run's verdict for every `FULL_JOURNEY` step — FAIL is a red (its detail is the
///   cause, with each node's state), NOT-RUN is a step the simulator cannot yet drive;
/// - the same record older than the newest node or wallet source is STALE: the source changed and the journey has not run;
/// - `scratchpad/restart-census.tsv`: the latest census's CHANGED fields — state a production restart lost or changed;
/// - the two production entry points (`main.rs`, `serve.rs`) calling a boot step themselves instead of `Node::boot` — the
///   drift that let the in-process node forget the @username registry, and that the simulator's restart would not see.
/// Every route the ADVERSARIAL ROUTE HARNESS drove on the CURRENT source: the `route-adversary` coverage rows of
/// `harness::netsim::journey_tests::sim_every_node_route_fails_closed_under_hostile_input_and_the_peer_holds_the_same_state`
/// (B1 (i), 2026-10-22), under the same rule as the simulator coverage below — a row older than the newest node or wallet
/// source no longer counts. A route it drove answered fail-closed to the whole hostile corpus (malformed, oversized,
/// overflowing, wrong lane, traversal, replayed, out of order) with the peer's every field unchanged, which is the
/// measurement the "node route with no adversarial test" row says is missing; an adversarial test NAMING the path stays
/// the other way to close it. The harness is recorded only when it PASSED (lane_run writes the ledgers of a green run).
/// This is the HOLE SCANNER (a test-only census of the tree's ledgers) reading the simulator's coverage record — no node
/// state, no authority, nothing the node holds; the same read `simulator_holes` below makes of `sim-coverage.tsv`.
fn adversary_driven_routes() -> Vec<(String, String)> {
    coverage_rows_on_current_source("route-adversary", "route")
        .into_iter()
        .map(|r| {
            let (m, p) = r.split_once(' ').unwrap_or(("ANY", r.as_str()));
            (m.to_string(), p.to_string())
        })
        .collect()
}

/// Every decode DOOR the decode-door replay drove green on the CURRENT source (the `decode-fuzz` rows of kind
/// `decode-door`, B1 (ii) 2026-10-22, `harness::fuzz::decode_doors_tests`): a site whose door is here answered the kept
/// corpus, every recorded crash input and the seeded hostile bytes with no panic and no hang — the measurement the
/// "decode of outside bytes no fuzzer reaches" row says is missing. The site → door map is the site's own text
/// (`surface_census::decode_door_for`); a site naming no door stays open.
fn fuzz_driven_decode_doors() -> Vec<String> {
    coverage_rows_on_current_source("decode-fuzz", "decode-door")
}

/// The `name` column of every `sim-coverage.tsv` row of `run` and `kind` written by lane_run from a GREEN run on the
/// current source — a row older than the newest node or wallet source no longer counts.
fn coverage_rows_on_current_source(run: &str, kind: &str) -> Vec<String> {
    let dir = crate::harness::scratchpad_dir();
    let node_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let wallet_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../monerousd-wallet-v2/src-tauri/src");
    let since = [newest_mtime(&node_src), newest_mtime(&wallet_src)].into_iter().flatten().max().map(local_ts).unwrap_or_default();
    // O1-INFINITY-REVIEWED: the scanner's own test ledger (scratchpad/sim-coverage.tsv, written by lane_run from a green harness run), read by a #[cfg(test)] census — not node state, not an authority the node rebuilds; the node holds nothing here
    let ledger = std::fs::read_to_string(dir.join("sim-coverage.tsv")).unwrap_or_default();
    ledger
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() >= 4 && f[0] >= since.as_str() && f[1] == run && f[2] == kind).then(|| f[3].to_string())
        })
        .collect()
}

fn simulator_holes() -> Vec<Hole> {
    let mut h = Vec::new();
    let dir = crate::harness::scratchpad_dir();
    let node_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let wallet_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../monerousd-wallet-v2/src-tauri/src");
    let newest_src = [newest_mtime(&node_src), newest_mtime(&wallet_src)].into_iter().flatten().max();
    let journey = std::fs::read_to_string(dir.join("sim-journey.tsv")).unwrap_or_default();
    let latest_ts = journey.lines().filter_map(|l| l.split('\t').next()).max().unwrap_or("").to_string();
    if latest_ts.is_empty() {
        h.push(hole("simulator record is stale", "the full node journey", "it has never run (scratchpad/sim-journey.tsv is empty)"));
    } else {
        let rec_mtime = std::fs::metadata(dir.join("sim-journey.tsv")).and_then(|m| m.modified()).ok();
        let stale = matches!((rec_mtime, newest_src), (Some(r), Some(s)) if s > r);
        if stale {
            h.push(hole(
                "simulator record is stale",
                "the full node journey",
                format!("its latest run ({latest_ts}) is older than the newest node/wallet source — run sim_journey_tier1 again"),
            ));
        }
        for (id, what) in crate::harness::netsim::journey::FULL_JOURNEY.iter() {
            let row = journey.lines().filter(|l| l.starts_with(&latest_ts)).find(|l| l.split('\t').nth(2) == Some(*id));
            let (v, detail) = row
                .map(|l| {
                    let f: Vec<&str> = l.splitn(5, '\t').collect();
                    (f.get(3).copied().unwrap_or("NOT-RUN").to_string(), f.get(4).copied().unwrap_or("").to_string())
                })
                .unwrap_or(("NOT-RUN".to_string(), "absent from the latest run".to_string()));
            match v.as_str() {
                "PASS" => {}
                "FAIL" => h.push(hole("simulated journey step FAILED", format!("{id} {what}"), detail)),
                _ => h.push(hole("simulated journey step has no arm", format!("{id} {what}"), detail)),
            }
        }
    }
    let census = std::fs::read_to_string(dir.join("restart-census.tsv")).unwrap_or_default();
    let census_ts = census.lines().filter_map(|l| l.split('\t').next()).max().unwrap_or("").to_string();
    if census_ts.is_empty() {
        h.push(hole("simulator record is stale", "the restart-equivalence census", "it has never run"));
    } else {
        for l in census.lines().filter(|l| l.starts_with(&census_ts)) {
            let f: Vec<&str> = l.split('\t').collect();
            if f.get(3) == Some(&"CHANGED") {
                h.push(hole(
                    "state changed by a production restart",
                    format!("{} · Node::{}", f.get(1).unwrap_or(&"?"), f.get(2).unwrap_or(&"?")),
                    format!("{} B before → {} B after the restart ({census_ts})", f.get(4).unwrap_or(&"?"), f.get(5).unwrap_or(&"?")),
                ));
            }
        }
    }
    // ⭐ DB-402 R1 — THE REPLICATED-STATE CENSUS: each lane's latest row set; a replicated field that DIFFERS across two nodes
    // holding the same chain (or that nothing reads — UNREAD) is a node standing on local truth (DB-401's class).
    // O1-INFINITY-REVIEWED: the hole SCANNER (a cfg(test) harness) reads the simulator's ledger to report holes; no node
    // reads it and no state is reconstructed from it — the node's authority is untouched.
    match std::fs::read_to_string(dir.join("replica-census.tsv")) {
        Err(_) => h.push(hole("simulator record is stale", "the replicated-state census (DB-402 R1)", "it has never run")),
        Ok(rows) => {
            let rows: Vec<Vec<&str>> = rows.lines().map(|l| l.split('\t').collect::<Vec<_>>()).filter(|f| f.len() >= 6).collect();
            let mut lanes: Vec<&str> = rows.iter().map(|f| f[2]).collect();
            lanes.sort_unstable();
            lanes.dedup();
            // THE NEWEST MEASUREMENT OF A FIELD WINS (the pin ledger's rule, surface_census::pin_ledger): a DIFFERS row is superseded
            // when a LATER census run of any lane measured the same field agreeing (SAME) or classed it node-local, exactly as a red
            // pin is superseded by a later pass. A retired lane's last row set otherwise stood forever (MEASURED 2026-11-03: 39 rows
            // from lanes last run 10-23…10-29, every field but one SAME on the 11-03 pin and join3 runs). A red no later run measured
            // stands: a divergence stays a hole until a run shows the field agreeing.
            let newest_field_verdict = |field: &str| rows.iter().filter(|f| f[3] == field).max_by(|a, b| a[0].cmp(b[0])).map(|f| (f[0], f[4]));
            for lane in lanes {
                let Some(ts) = rows.iter().filter(|f| f[2] == lane).map(|f| f[0]).max() else { continue };
                for f in rows.iter().filter(|f| f[2] == lane && f[0] == ts && matches!(f[4], "DIFFERS" | "UNREAD")) {
                    if matches!(newest_field_verdict(f[3]), Some((at, v)) if at > ts && !matches!(v, "DIFFERS" | "UNREAD")) {
                        continue;
                    }
                    h.push(hole(
                        "replicated state not one function of the chain",
                        format!("Node::{} ({} lane)", f[3], lane),
                        format!("{} across nodes holding the same chain at a quiet point — bytes per node {} ({ts})", f[4], f[5]),
                    ));
                }
            }
        }
    }
    // ⭐ DB-402 R3 — THE WIRE-LOSS CENSUS: every conversion fn the tree declares, discovered by the one script.
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/wire_loss_census.py");
    match std::process::Command::new("python3").arg(&script).args([std::ffi::OsStr::new("--root"), node_src.as_os_str()]).output() {
        Err(e) => h.push(hole("simulator record is stale", "the wire-loss census (DB-402 R3)", format!("python3 could not run it: {e}"))),
        Ok(o) => {
            for l in String::from_utf8_lossy(&o.stdout).lines().filter(|l| l.starts_with("[wire-loss] DROP\t") || l.starts_with("[wire-loss] STALE")) {
                let f: Vec<&str> = l.split('\t').collect();
                let name = match f.get(3) {
                    Some(x) => x.to_string(),
                    None => l.to_string(),
                };
                let at = if f.len() >= 3 { f[1..3].join(" ") } else { l.to_string() };
                h.push(hole("conversion drops a carried field", name, at));
            }
        }
    }
    // THE FAST LANE: a red there is a red (it runs the same journey with the bound band double, in seconds).
    let fast = std::fs::read_to_string(dir.join("sim-journey-fast.tsv")).unwrap_or_default();
    let fast_ts = fast.lines().filter_map(|l| l.split('\t').next()).max().unwrap_or("").to_string();
    for l in fast.lines().filter(|l| !fast_ts.is_empty() && l.starts_with(&fast_ts)) {
        let f: Vec<&str> = l.splitn(5, '\t').collect();
        if f.get(3) == Some(&"FAIL") {
            h.push(hole("simulated journey step FAILED", format!("{} (fast lane)", f.get(2).unwrap_or(&"?")), f.get(4).copied().unwrap_or("").to_string()));
        }
    }
    // COVERAGE: every route, peer message and wallet command the TREE declares, against what a simulator run touched on the
    // CURRENT source (a row older than the newest node/wallet source no longer counts — the simulator must run again).
    let since = newest_src.map(local_ts).unwrap_or_default();
    let cov = std::fs::read_to_string(dir.join("sim-coverage.tsv")).unwrap_or_default();
    let touched: Vec<(String, String)> = cov
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() >= 4 && f[0] >= since.as_str()).then(|| (f[2].to_string(), f[3].to_string()))
        })
        .collect();
    let eco = crate::harness::surface_census::ecosystem();
    // No coverage row on the current source at all = the simulator has not run since the source changed: every surface it would
    // report is MEASUREMENT DEBT (one category, counted apart), not a blind spot. Rows on this source exist and a surface is still
    // untouched = a surface the simulator does not exercise: the blind spot stands.
    let cov_cat: &'static str =
        if touched.is_empty() { "simulator coverage not yet re-run on this source" } else { "surface the simulator never exercised" };
    for (m, p, at) in crate::harness::surface_census::routes(&eco) {
        let hit = touched.iter().filter(|(k, _)| k == "route").any(|(_, n)| {
            let (tm, tp) = n.split_once(' ').unwrap_or(("ANY", n.as_str()));
            crate::harness::sim_coverage::route_covers(tm, tp, &m, &p)
        });
        if !hit {
            h.push(hole(cov_cat, format!("route {m} {p}"), format!("no simulator run on the current source called it — {at}")));
        }
    }
    for (en, v, _) in crate::harness::surface_census::wire_messages(&eco) {
        if !touched.iter().any(|(k, n)| k == "wire" && *n == v) {
            h.push(hole(cov_cat, format!("message {en}::{v}"), "no simulated node received it on the current source".to_string()));
        }
    }
    for (name, at, _) in crate::harness::surface_census::wallet_commands(&eco) {
        if !touched.iter().any(|(k, n)| k == "wallet" && *n == name) {
            h.push(hole(cov_cat, format!("wallet command {name}"), format!("no simulated wallet drove it (journey step T1.7 drives the wallet) — {at}")));
        }
    }
    const BOOT_STEPS: [&str; 7] = [
        "enable_persist(",
        "enable_block_window(",
        "enable_dir_persist(",
        "enable_custody_opening_persist(",
        "set_decider_verifier(",
        "set_site_verifier(",
        "set_finality_verifier(",
    ];
    for f in ["main.rs", "serve.rs"] {
        let src = std::fs::read_to_string(node_src.join(f)).unwrap_or_default();
        if !src.contains(".boot(") {
            h.push(hole("boot step outside Node::boot", f, "this entry point does not boot through Node::boot"));
        }
        for (n, line) in src.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for step in BOOT_STEPS {
                if code.contains(&format!(".{step}")) {
                    h.push(hole("boot step outside Node::boot", format!("{f}:{}", n + 1), format!("calls `{step}…)` itself: a restart here differs from the one the simulator runs")));
                }
            }
        }
    }
    h
}

/// A file time as local `YYYY-MM-DDTHH:MM:SS` — the ledgers' timestamp format — so a row can be compared with it.
fn local_ts(t: std::time::SystemTime) -> String {
    let secs = t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    std::process::Command::new("date")
        .args(["-r", &secs.to_string(), "+%Y-%m-%dT%H:%M:%S"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// The newest modification time under `dir` (recursive, backups excluded).
fn newest_mtime(dir: &std::path::Path) -> Option<std::time::SystemTime> {
    let mut newest = None;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") && !p.to_string_lossy().contains(".pre") {
                let t = e.metadata().and_then(|m| m.modified()).ok();
                if t > newest {
                    newest = t;
                }
            }
        }
    }
    newest
}

/// The circuit half: `scratchpad/holes-circuit.tsv` rows `tier \t kind \t category \t name \t detail`.
fn circuit_holes() -> Vec<Hole> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let file = crate::harness::scratchpad_dir().join("holes-circuit.tsv");
    let Ok(text) = std::fs::read_to_string(&file) else {
        return vec![Hole {
            tier: 0,
            kind: UNMEASURED,
            category: "circuit sweep never ran",
            name: "every AIR gate".into(),
            detail: "run scratchpad/holes.sh: no strict-mode degree / free-witness / decorative census result exists".into(),
        }];
    };
    let mut h = Vec::new();
    let swept = std::fs::metadata(&file).and_then(|m| m.modified()).ok();
    if newest_mtime(&root.join("vendor/Plonky3/usdm-decider/src")) > swept {
        h.push(Hole {
            tier: 0,
            kind: UNMEASURED,
            category: "circuit sweep is stale",
            name: "every AIR gate".into(),
            detail: "the decider changed after the last strict sweep: re-run scratchpad/holes.sh".into(),
        });
    }
    for l in text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let c: Vec<&str> = l.splitn(5, '\t').collect();
        if c.len() < 5 {
            continue;
        }
        let kind = match c[1] {
            "EXPLOIT" => EXPLOIT,
            "UNMEASURED" => UNMEASURED,
            _ => BLIND,
        };
        let category: &'static str = match c[2] {
            "circuit gate never censused by a strict prove" => "circuit gate never censused by a strict prove",
            "circuit census failure" => "circuit census failure",
            "strict-mode test failure" => "strict-mode test failure",
            _ => "circuit sweep finding",
        };
        h.push(Hole { tier: c[0].parse().unwrap_or(0), kind, category, name: c[3].to_string(), detail: c[4].to_string() });
    }
    h
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::every_hole;

    /// The cause attribution is ARMED: a planted failure is attributed to its panic site, a later pass reads stale, and a
    /// red nobody recorded says so — never a silent "unknown".
    #[test]
    fn a_red_is_attributed_to_its_recorded_panic_and_a_later_pass_reads_stale() {
        use super::{cause_with, hole, RedCause};
        let mut fails = std::collections::HashMap::new();
        fails.insert("the_planted_red_pin_fails".to_string(), ("src/node.rs:42".to_string(), "boom 7".to_string(), "2026-10-06T01:00:00".to_string()));
        let mut latest = std::collections::HashMap::new();
        let red = hole("known-red pin", "the_planted_red_pin_fails", "");
        assert_eq!(
            cause_with(&red, &fails, &latest),
            RedCause::Panicked { site: "src/node.rs:42".into(), message: "boom 7".into(), at: "2026-10-06T01:00:00".into() }
        );
        latest.insert("the_planted_red_pin_fails".to_string(), ("2026-10-06T02:00:00".to_string(), true));
        assert_eq!(cause_with(&red, &fails, &latest), RedCause::LatestRunPassed { at: "2026-10-06T02:00:00".into() });
        // a later red with no captured cause never inherits the older panic
        latest.insert("the_planted_red_pin_fails".to_string(), ("2026-10-07T09:00:00".to_string(), false));
        assert_eq!(cause_with(&red, &fails, &latest), RedCause::NeverRecorded);
        assert!(super::cause_family("⛔ COULD NOT RAISE A REAL 2-NODE MESH: ⛔ STALE BINARY").is_some());
        assert!(super::cause_family("the joiner folds like its origin").is_none());
        let unknown = hole("known-red pin", "a_red_nobody_ever_recorded_failing", "");
        assert_eq!(cause_with(&unknown, &fails, &latest), RedCause::NeverRecorded);
    }

    /// THE SWEEP: prints every open hole, grouped by category, and the total. An INSTRUMENT, not a proof: it asserts only
    /// that it read every census (a census that cannot be read prints nothing and would read as "no holes").
    /// A hole whose only cause is a measurement not yet made is DEBT; a measured red never is — the rule would fail this test if a
    /// journey step that printed FAIL (cause never captured) were ever filed as debt, or a listed red with a recorded panic.
    #[test]
    fn a_measurement_not_yet_made_is_debt_and_a_measured_red_never_is() {
        use std::collections::HashMap;
        let mut fails = HashMap::new();
        let mut latest = HashMap::new();
        let stale = super::hole("simulator record is stale", "the full node journey", "older than the source");
        let listed_unrun = super::hole("known-red pin", "node::pins::the_planted_listed_red", "RED in the tree");
        let listed_passed = super::hole("known-red pin", "node::pins::the_planted_listed_pass", "RED in the tree");
        let listed_panicked = super::hole("known-red pin", "node::pins::the_planted_listed_panic", "RED in the tree");
        let step_failed = super::hole("simulated journey step FAILED", "T2.3 the_planted_step", "DIFFERS on 3 fields");
        let coverage_debt = super::hole("simulator coverage not yet re-run on this source", "route GET /x", "");
        let coverage_blind = super::hole("surface the simulator never exercised", "route GET /x", "");
        latest.insert("the_planted_listed_pass".to_string(), ("2026-10-07T09:00:00".to_string(), true));
        fails.insert("the_planted_listed_panic".to_string(), ("src/node.rs:42".to_string(), "boom 7".to_string(), "2026-10-07T09:00:00".to_string()));
        latest.insert("the_planted_listed_panic".to_string(), ("2026-10-07T09:00:00".to_string(), false));
        let debt = |h: &super::Hole| super::is_measurement_debt_with(h, &fails, &latest);
        assert!(debt(&stale) && debt(&listed_unrun) && debt(&listed_passed) && debt(&coverage_debt), "a measurement not yet made is debt");
        assert!(!debt(&listed_panicked), "a listed red WITH a recorded panic is a hole, not debt");
        assert!(!debt(&step_failed), "a journey step that printed FAIL is a measured red, never debt, whatever its cause index says");
        assert!(!debt(&coverage_blind), "a surface the simulator ran past is a blind spot, not debt");
        // THE INSTRUMENT CLASS: a red whose cause is the absent binary or a fixture's calibration measured no chain state.
        let step_unbuilt = super::hole("simulated journey step FAILED", "T1.1 (fast lane)", "the real wallet binary is not built at /x");
        let pin_calibration = super::hole("pin RED in its latest recorded run", "node::pins::the_planted_calibration_red", "");
        fails.insert(
            "the_planted_calibration_red".to_string(),
            ("src/harness/netsim.rs:7".to_string(), "CALIBRATION: the joiner reaches one chain".to_string(), "2026-11-03T03:00:00".to_string()),
        );
        latest.insert("the_planted_calibration_red".to_string(), ("2026-11-03T03:00:00".to_string(), false));
        let debt = |h: &super::Hole| super::is_measurement_debt_with(h, &fails, &latest);
        assert!(debt(&step_unbuilt) && debt(&pin_calibration), "an instrument red is a measurement not yet made");
        assert!(!debt(&listed_panicked) && !debt(&step_failed), "a red with a chain cause stays a hole");
        // the split keeps every hole: nothing is dropped, only sorted
        let all = vec![stale.clone(), listed_panicked.clone(), step_failed.clone()];
        let (h, d) = all.into_iter().partition::<Vec<_>, _>(|x| !debt(x));
        assert_eq!((h.len(), d.len()), (2, 1));
    }

    #[test]
    fn print_every_hole_in_the_ecosystem() {
        use super::TIER_NAMES;
        let (all, debt) = super::split_debt(every_hole());
        // THE FUNDS-FIRST COUNT (user 2026-11-03: "We are prioritizing funds loss bugs and funds loss exploits. The cash layer
        // must be ironclad"): a HOLE is a MEASURED exploit — a red with a chain cause, a census DIFFERS, a value door open. A
        // BLIND SPOT (a surface no test reaches) or an UNMEASURED claim is the BACKLOG: listed in full, never counted as a hole,
        // never a gate, until a run turns it into a measured red.
        let (holes, backlog): (Vec<_>, Vec<_>) = all.into_iter().partition(|h| h.kind == super::EXPLOIT);
        let (_, coverage) = crate::harness::surface_census::surface_holes();
        eprintln!("\n══════════ EVERY HOLE IN THE ECOSYSTEM ({} total) · MEASUREMENT DEBT {} ══════════", holes.len(), debt.len());
        eprintln!("\nCOVERAGE (every universe read from the tree):");
        for c in &coverage {
            eprintln!("  · {c}");
        }
        eprintln!("\nSUMMARY            HOLES (measured exploits)  ·  BACKLOG: BLIND SPOT  UNMEASURED   total");
        for (t, name) in TIER_NAMES.iter().enumerate() {
            let n = |k: &str| holes.iter().chain(backlog.iter()).filter(|h| h.tier as usize == t && h.kind == k).count();
            let (e, b, u) = (n(super::EXPLOIT), n(super::BLIND), n(super::UNMEASURED));
            let short = name.split(" — ").next().unwrap_or(name);
            eprintln!("  {short:<16} {e:>7}  {b:>10}  {u:>10}  {:>6}", e + b + u);
        }
        // MEASUREMENT DEBT (user 2026-10-27): what has not been measured on this source yet — never a tier hole, never a link's work.
        let mut debt_cat: Vec<(&str, usize)> = Vec::new();
        for h in &debt {
            match debt_cat.iter_mut().find(|(c, _)| *c == h.category) {
                Some(e) => e.1 += 1,
                None => debt_cat.push((h.category, 1)),
            }
        }
        debt_cat.sort_by(|a, b| b.1.cmp(&a.1));
        eprintln!(
            "\nMEASUREMENT DEBT {} — not holes: measurements not yet made on this source (clear_debt.sh, the watch and the farm make them at zero tokens; R1 needs zero):",
            debt.len()
        );
        for (c, n) in &debt_cat {
            eprintln!("  [{n:>3}] {c}");
        }
        // THE CAUSES (user 2026-10-06): the reds grouped by what broke, then the rest named for what they are.
        let reds = holes.iter().filter(|h| super::RED_CATEGORIES.contains(&h.category)).count();
        let groups = super::cause_groups(&holes);
        eprintln!("\nROOT CAUSES OF THE {reds} FAILING TEST(S) — {} distinct cause(s), largest first:", groups.len());
        for g in &groups {
            eprintln!("  [{:>3}] {}", g.reds.len(), g.signature);
            for r in g.reds.iter().take(3) {
                eprintln!("        e.g. {r}");
            }
        }
        let mut by_cat: Vec<(&str, usize)> = Vec::new();
        for h in &backlog {
            match by_cat.iter_mut().find(|(c, _)| *c == h.category) {
                Some(e) => e.1 += 1,
                None => by_cat.push((h.category, 1)),
            }
        }
        by_cat.sort_by(|a, b| b.1.cmp(&a.1));
        eprintln!(
            "\nBACKLOG {} — NOT HOLES: each is a surface no test measures yet (the cause is the missing instrument), never a gate:",
            backlog.len()
        );
        for (c, n) in &by_cat {
            eprintln!("  [{n:>3}] {c}");
        }
        for (t, tname) in TIER_NAMES.iter().enumerate() {
            let in_tier: Vec<_> = holes.iter().chain(backlog.iter()).filter(|h| h.tier as usize == t).collect();
            if in_tier.is_empty() {
                continue;
            }
            let n_holes = in_tier.iter().filter(|h| h.kind == super::EXPLOIT).count();
            eprintln!("\n████ {tname} ({n_holes} hole(s) · {} backlog)", in_tier.len() - n_holes);
            let mut last = ("", "");
            for h in in_tier {
                if (h.kind, h.category) != last {
                    let count =
                        holes.iter().chain(backlog.iter()).filter(|x| x.tier == h.tier && x.kind == h.kind && x.category == h.category).count();
                    let tag = if h.kind == super::EXPLOIT { "" } else { "BACKLOG · " };
                    eprintln!("\n■ [{tag}{}] {} ({count})", h.kind, h.category);
                    last = (h.kind, h.category);
                }
                if h.detail.is_empty() {
                    eprintln!("  • {}", h.name);
                } else {
                    eprintln!("  • {} — {}", h.name, h.detail);
                }
                if super::RED_CATEGORIES.contains(&h.category) {
                    match super::cause_of(h) {
                        super::RedCause::Panicked { site, message, at } => eprintln!("      CAUSE ({at}): {site} — {message}"),
                        super::RedCause::LatestRunPassed { at } => eprintln!("      CAUSE: none — the latest recorded run PASSED ({at}); the listing is stale"),
                        super::RedCause::NeverRecorded => eprintln!("      CAUSE: not captured — a recorded red whose panic site red-causes.tsv does not hold (read its log)"),
                    }
                }
            }
        }
        if !debt.is_empty() {
            eprintln!("\n████ MEASUREMENT DEBT ({}) — listed, not counted as holes", debt.len());
            let mut last = "";
            for h in &debt {
                if h.category != last {
                    eprintln!("\n■ [DEBT] {} ({})", h.category, debt.iter().filter(|x| x.category == h.category).count());
                    last = h.category;
                }
                eprintln!("  • {}{}", h.name, if h.detail.is_empty() { String::new() } else { format!(" — {}", h.detail) });
            }
        }
        let verdict = if holes.is_empty() { "zero measured exploits on every tier" } else { "measured exploits open" };
        eprintln!(
            "\n══════════ {} HOLE(S) — {verdict} · {} BACKLOG (not holes) · MEASUREMENT DEBT {} ══════════\n",
            holes.len(),
            backlog.len(),
            debt.len()
        );
        assert!(
            !crate::harness::value_creation::SITES.is_empty() && !crate::harness::privacy::SURFACES.is_empty(),
            "the sweep could not read its censuses"
        );
    }
}
