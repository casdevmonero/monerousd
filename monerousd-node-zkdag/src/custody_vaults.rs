// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ CUSTODY VAULTS (2026-11-10) — THE BONDED SET IS CUT INTO CUSTODY COMMITTEES OF A FIXED SIZE, SO NO BRIDGE
//! OPERATION EVER GROWS WITH THE NUMBER OF NODES THAT BOND. (AGENTS.md §2 SAFE AT SCALE; user 2026-11-10: "close the
//! monero scaling problem and make it secure the first time you write it … verify that all of our native assets
//! bridges scale infinitely with the amount of nodes who bond".)
//!
//! WHAT IT REPLACES, READ ON main e392657b (docs/BRIDGE-SCALE-VAULTS-SPEC-20261110.md §1): the custody set of each
//! native asset was the WHOLE bonded custodian set. The one Monero multisig wallet for that set cannot be formed at the
//! 17th custodian (Monero's multisig stops at 16 signers); a deposit or a burn carried one sealed envelope per
//! custodian and was refused at decode past 256; a deposit or burn was about half a megabyte at 100 custodians; the
//! Bitcoin leaf's witness and the epoch dealing grew with the set; and one bond change re-formed custody of the whole
//! reserve.
//!
//! THE SHAPE. A VAULT is at most [`VAULT_MAX`] custodians and signs with two thirds of its own members ([`quorum`]).
//! The vaults are a PURE FUNCTION OF THE BONDED SET ([`form`]): the custodians in seniority order — the height their
//! bond became active, then their id — cut into consecutive vaults of 16, the last two shared evenly when fewer than
//! [`VAULT_MIN`] would be left over. No table is stored and none is carried in a snapshot or a certified bundle: a node
//! that holds the validator set holds the vaults, so a node that adopted a certified state computes the same vaults as
//! a node that has followed the chain since genesis. (The first cut of this module kept a table updated at each bond
//! event. That table would have been one more word for the snapshot, the bundle and the field censuses to carry and
//! for an adopter to be handed; state that is a function of state already carried is the borrowed shape, Ethereum's
//! state-transition function.)
//!   * Up to 16 custodians are ONE vault — the custody set exactly as it was.
//!   * A custodian is in exactly one vault; a vault holds [`VAULT_MIN`] to [`VAULT_MAX`] members once there are two.
//!   * A custodian that BONDS is the most junior: it joins the last vault, or splits the last one. The other vaults
//!     are unchanged.
//!   * A custodian that LEAVES changes its own vault and the vaults junior to it (each passes one member up) — and
//!     the vault just senior to it only when the last two are re-shared. No vault further up changes.
//! A vault's identity is the digest of its member set ([`vault_id`]): a change of membership is a new vault, which is
//! what a custody wallet is anyway (its keys are its members').
//!
//! WHAT A VAULT'S SIZE DOES NOT CARRY: its safety. A vault may hold no more than its own members' bond covers
//! ([`cover`]): the cheapest two thirds of ANY vault forfeit more than the vault may hold. That is why seniority order
//! is enough — an operator that bonds eleven nodes in a row owns a vault's quorum and loses more than that vault can
//! ever hold — and why a small vault is a small vault, not a weak one.
//!
//! SCALE (§9.6 question 7): `form` is one pass over the bonded set; nothing here grows with height, notes or the
//! reserve, and nothing is stored. A bridge operation done by one vault costs the same at 16 custodians and at 16,000.
//!
//! BORROWED: THORChain's Asgard vaults (a bounded signer set per vault, more vaults as nodes bond, a vault's value
//! under its bond, funds migrated when membership churns) and Ethereum's committees (a fixed committee size over an
//! unbounded validator set, computed from the validator registry by any node that holds it).
//! cons: the 17th custodian turns one vault into two (two wallets where there was one); a custodian that leaves
//! re-forms the vaults junior to it (THORChain re-forms all of its vaults at each churn); a vault's capacity is its own
//! members' bond, not the whole set's.

/// ⭐ IS THE CUT LIVE ON THIS CHAIN? YES (lane vaults, 2026-11-12, spec docs/BRIDGE-SCALE-VAULTS-SPEC-20261110.md §3e.4).
/// Everything a cut custody set needs to RUN is built and pinned at 16, 17 and 160 custodians (a ledger per vault, the
/// one signing rule, the ride, legs and lanes by vault, routing), and everything it needs to CHANGE is built and pinned
/// too: a joining custodian is handed its vault's openings and coin list (`node::opening_share`, `btc_payout::CoinShare`);
/// a changed vault takes the key of its members and its coins follow (`Class::VaultKey`, the Bitcoin consolidation, the
/// Monero sweep, their fees booked by `Class::ReserveCost`); a thinned vault's ledgers are merged, coins first
/// (`Class::VaultMerge`); the weekly rotation mixes seats between vaults (R5); a vault past its bound moves eighths of
/// its ledgers to a vault with room (`Class::VaultRebalance`); a leaver's collateral returns only when no alive key names
/// it, and a vault that holds it past its window pays it the quarter (R4b). So the validator set answers the seated cut
/// (`ValidatorSet::custody_vaults`): vaults of at most sixteen. Up to sixteen custodians the answer is the one vault it
/// always was. Turned on in a landing that says FORMAT: past sixteen custodians it changes what nodes agree on.
/// Sizes run: pins at 16, 17, 25, 40, 160 and 1,600 custodians (the custody lifecycle model at every size up to 80);
/// real nodes at two custodians (one vault) — a real-node run at seventeen needs more machines than this one.
pub const CUT_LIVE: bool = true;

#[cfg(test)]
thread_local! {
    /// Test seam (as `epoch_deal_tx::TEST_EPOCH_MS`): a pin turns the cut on for its own thread, to measure what is built
    /// on it. Production reads [`CUT_LIVE`] alone.
    pub static TEST_CUT_LIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the custody set is cut into vaults: [`CUT_LIVE`] (a pin may turn it on for its own thread).
#[must_use]
pub fn cut_live() -> bool {
    #[cfg(test)]
    if TEST_CUT_LIVE.with(std::cell::Cell::get) {
        return true;
    }
    CUT_LIVE
}

/// The most custodians in one vault: Monero's multisig signer limit (`MULTISIG_MAX_SIGNERS`, cryptonote_config.h), the
/// smallest hard limit among the native assets. One size for all of them, so one vault holds them all.
pub const VAULT_MAX: usize = 16;
/// The fewest custodians in a vault once there is more than one: half a full vault. A lone vault may be smaller — it
/// is the whole bonded set.
pub const VAULT_MIN: usize = VAULT_MAX / 2;

/// The signers a vault of `size` members needs: two thirds of its own members, rounded up — the custody tally's rule
/// (`xmr_custody::threshold`), per vault.
#[must_use]
pub fn quorum(size: usize) -> usize {
    (2 * size + 2) / 3
}

/// A vault's identity: its member set, hashed. Order-free, and a different set is a different vault.
#[must_use]
pub fn vault_id(members: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted = members.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut h = blake3::Hasher::new_derive_key("MonerousD custody vault id v1");
    h.update(&(sorted.len() as u64).to_le_bytes());
    for id in &sorted {
        h.update(id);
    }
    *h.finalize().as_bytes()
}

/// How many members each vault takes from the seniority order, first vault first: `n` custodians in vaults of
/// [`VAULT_MAX`], the last two sharing evenly when fewer than [`VAULT_MIN`] would be left over.
#[must_use]
pub fn sizes(n: usize) -> Vec<usize> {
    if n == 0 {
        return Vec::new();
    }
    let (full, rest) = (n / VAULT_MAX, n % VAULT_MAX);
    let mut out = vec![VAULT_MAX; full];
    if rest > 0 {
        if rest >= VAULT_MIN || full == 0 {
            out.push(rest);
        } else {
            // the last full vault and the few left over share evenly: both land in VAULT_MIN..=VAULT_MAX
            let both = VAULT_MAX + rest;
            let first = (both + 1) / 2;
            out[full - 1] = first;
            out.push(both - first);
        }
    }
    out
}

/// THE VAULTS of a bonded set. `by_seniority` names each bonded custodian exactly once, most senior first (the height
/// its bond became active, then its id). A vault's members come back sorted by id; the vaults in seniority order.
#[must_use]
pub fn form(by_seniority: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let mut at = 0usize;
    sizes(by_seniority.len())
        .into_iter()
        .map(|s| {
            let mut v = by_seniority[at..at + s].to_vec();
            at += s;
            v.sort_unstable();
            v
        })
        .collect()
}

/// The index of the vault `id` sits in.
#[must_use]
pub fn vault_of(vaults: &[Vec<[u8; 32]>], id: &[u8; 32]) -> Option<usize> {
    vaults.iter().position(|v| v.binary_search(id).is_ok())
}

// ───────────────────────────── SEATS: ONE VAULT CHANGES PER BOND EVENT, WHATEVER THE BONDED SET ─────────────────────────────
// The seniority cut above ([`form`]) is a pure function, and it pays for that: a custodian that leaves shifts every
// junior vault by one member, and every vault whose members change needs its openings handed on and its coins moved.
// One leave at a thousand custodians would re-form about sixty vaults. So a custodian holds a SEAT: a number it takes
// when it bonds and keeps until it leaves (or a split of its vault moves it). Vault `k` is seats `16k … 16k + 15`.
//   * A BOND takes a seat by THE DRAW ([`draw_seat`]): among the free seats of vaults that already hold eight members,
//     chosen by chain randomness; one vault gains one member. When no such seat exists a full vault splits in two.
//   * A LEAVE frees its seat: its own vault loses one member; no other vault changes.
// The seat is one word per custodian, carried with the seat like its activation height (`ValidatorSet::custody_seats`).
// BORROWED: THORChain's vault membership is state the chain keeps, changed at churn. cons: a vault thinned under eight
// takes no newcomer while a vault of eight exists (it merges its ledgers out and its members leave or bond again); a
// vault's index outlives its members.
// [`lowest_free_seat`] stays for a set rebuilt from a carrier that names no seats (the same on every node that reads the
// same carrier) and as the draw pin's control.

/// The vault a seat belongs to.
#[must_use]
pub fn vault_of_seat(seat: u64) -> usize {
    usize::try_from(seat / VAULT_MAX as u64).unwrap_or(usize::MAX)
}

/// The seat a custodian that bonds now takes: the lowest number no bonded custodian holds.
#[must_use]
pub fn lowest_free_seat(taken: &std::collections::BTreeSet<u64>) -> u64 {
    let mut next = 0u64;
    for s in taken {
        if *s != next {
            break;
        }
        next += 1;
    }
    next
}

/// What seating one bond did: the newcomer's seat and, when a full vault was split to make room, the seats that
/// moved (`(old, new)`, sorted by the old seat).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seating {
    pub seat: u64,
    pub moved: Vec<(u64, u64)>,
}

/// One draw from `entropy`: a number below `n` (`n > 0`), domain-separated by `tag` and `i`.
fn draw(entropy: &[u8; 32], tag: &str, i: u64, n: usize) -> usize {
    let mut h = blake3::Hasher::new_derive_key(tag);
    h.update(entropy);
    h.update(&i.to_le_bytes());
    let mut w = [0u8; 8];
    w.copy_from_slice(&h.finalize().as_bytes()[..8]);
    (u64::from_le_bytes(w) % n as u64) as usize
}

/// ⭐⭐ THE SEAT A BOND TAKES — THE DRAW (replaces [`lowest_free_seat`] before the cut goes live). `taken` is every seat a
/// bonded custodian holds; `entropy` is chain randomness the bonder does not choose (the id of the block whose fold
/// seats the bond, with the bonder's id).
///   1. If a vault that ALREADY HOLDS EIGHT members has a free seat, the newcomer takes one of all such seats, drawn
///      uniformly. One vault gains one member.
///   2. If no vault holds eight yet (a young chain, or every vault thinned), it joins the fullest vault that has room
///      (the lowest index among equals) on its lowest free seat; the first custodian takes seat 0.
///   3. Otherwise every vault that holds eight is FULL: one of them, drawn, is SPLIT — a drawn half of its sixteen
///      members moves to the lowest vault index that has no member — and the newcomer takes a drawn seat among the
///      sixteen now free in the two halves. Two vaults change.
/// WHY (AI RESISTANT, and the reason lowest-free-seat is not the rule): under lowest-free-seat sixteen bonds in a row
/// own a whole vault, its quorum and every coin deposited to it past its authority. Under the draw a newcomer only
/// ever joins a vault that already holds eight older members, so a run of fresh bonds of any length is at most HALF
/// of any vault, and which vault each lands in is not the bonder's choice. What protects a vault is still its bound
/// (it stands behind no more than its cheapest quorum's bonds repay on its own word) — code and economics, not a
/// proof; the draw removes the cheap way around it. A bonder that also produces the seating block can re-roll its
/// draw at one block's work per try, which chooses among vaults that each keep eight older members.
/// A vault thinned under eight takes no newcomer while any vault holds eight: it merges its ledgers out
/// (`Class::VaultMerge`) and its members leave or bond again.
/// BORROWED: THORChain churns nodes into Asgard vaults by rule, never by the node's choice; a B-tree's node split (a
/// full bucket halves when it must take one more). SCALE: one or two vaults change per bond, whatever the bonded set;
/// one pass over the seats.
/// cons: a split re-keys two vaults at once (the split vault's coins are swept to its new member set's keys, and the
/// moved members hold no opening of the new vault's ledgers, which stand on their genesis pairs); a thinned vault's
/// members are idle until they leave.
#[must_use]
pub fn draw_seat(taken: &std::collections::BTreeSet<u64>, entropy: &[u8; 32]) -> Seating {
    let w = VAULT_MAX as u64;
    let mut count: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for s in taken {
        *count.entry(vault_of_seat(*s)).or_default() += 1;
    }
    let free_in = |v: usize| -> Vec<u64> { (0..w).map(|i| v as u64 * w + i).filter(|s| !taken.contains(s)).collect() };
    let roomy: Vec<usize> = count.iter().filter(|(_, c)| **c >= VAULT_MIN && **c < VAULT_MAX).map(|(v, _)| *v).collect();
    if !roomy.is_empty() {
        let free: Vec<u64> = roomy.iter().flat_map(|v| free_in(*v)).collect();
        return Seating { seat: free[draw(entropy, "MonerousD custody seat v1", 0, free.len())], moved: Vec::new() };
    }
    let full: Vec<usize> = count.iter().filter(|(_, c)| **c >= VAULT_MAX).map(|(v, _)| *v).collect();
    if full.is_empty() {
        let v = count.iter().max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0))).map_or(0, |(v, _)| *v);
        return Seating { seat: free_in(v)[0], moved: Vec::new() };
    }
    let from = full[draw(entropy, "MonerousD custody split v1", 0, full.len())];
    let to = (0usize..).find(|v| !count.contains_key(v)).unwrap_or(usize::MAX);
    // a drawn half: a Fisher–Yates shuffle of the sixteen seat offsets, the first eight move
    let mut order: Vec<u64> = (0..w).collect();
    for i in (1..order.len()).rev() {
        order.swap(i, draw(entropy, "MonerousD custody half v1", i as u64, i + 1));
    }
    let mut moved: Vec<(u64, u64)> = order[..VAULT_MIN].iter().enumerate().map(|(k, off)| (from as u64 * w + off, to as u64 * w + k as u64)).collect();
    moved.sort_unstable();
    let mut free: Vec<u64> = moved.iter().map(|(old, _)| *old).chain((VAULT_MIN as u64..w).map(|k| to as u64 * w + k)).collect();
    free.sort_unstable();
    Seating { seat: free[draw(entropy, "MonerousD custody seat v1", 1, free.len())], moved }
}

/// THE VAULTS of a seated custody set: `seats` names each bonded custodian once with its seat. Vault `k` holds the
/// custodians on seats `16k … 16k + 15`, sorted by id; the answer runs to the highest occupied vault, and a vault whose
/// seats are all free is EMPTY (its index stands: its ledgers are merged away when its last member leaves).
#[must_use]
pub fn by_seats(seats: &[(u64, [u8; 32])]) -> Vec<Vec<[u8; 32]>> {
    let Some(top) = seats.iter().map(|(s, _)| vault_of_seat(*s)).max() else { return Vec::new() };
    let mut out: Vec<Vec<[u8; 32]>> = vec![Vec::new(); top + 1];
    for (s, id) in seats {
        out[vault_of_seat(*s)].push(*id);
    }
    for v in &mut out {
        v.sort_unstable();
        v.dedup();
    }
    out
}

/// WHAT A VAULT MAY HOLD: three quarters of the bond of its CHEAPEST quorum. Any [`quorum`] of its members that moved
/// its coins, or attested a deposit that never happened, would forfeit at least the sum of the smallest `quorum` bonds
/// — four thirds of this figure — so taking a vault always costs more than the vault can hold. `bonds` are the vault's
/// members' bond weights, in any order. (The ledger's rule for the whole set is the same figure: a reserve of at most
/// half the bonded weight, against the two thirds of weight a theft forfeits.)
/// A vault signs two ways and the figure is under both: its custody wallets by COUNT ([`quorum`] members, the Monero
/// multisig's rule) and its chain statements by WEIGHT (two thirds of its members' bond, the ledger's one tally,
/// `psm::VaultQuorum`). The cheapest count quorum is the sum of the smallest `quorum` bonds; any weight quorum has
/// bonded at least two thirds of the vault's total. The cover is three quarters of the smaller.
#[must_use]
pub fn cover(bonds: &[u128]) -> u128 {
    let cheapest = forfeit(bonds);
    cheapest / 4 * 3 + (cheapest % 4) * 3 / 4
}

/// WHAT THE CHEAPEST SIGNING SET OF A VAULT FORFEITS: the least bond any set of its members that can sign for it has
/// at stake — the smaller of its cheapest count quorum (the smallest [`quorum`] bonds) and two thirds of its weight.
/// The ledger values this at the chain's own repayment floor to bound what the vault's quorum may sign for alone
/// (`PegLedger::vault_authority_usdm`): a vault never stands behind more than its own slashed bonds would repay.
#[must_use]
pub fn forfeit(bonds: &[u128]) -> u128 {
    let mut b = bonds.to_vec();
    b.sort_unstable();
    let by_count: u128 = b.iter().take(quorum(b.len())).fold(0u128, |a, x| a.saturating_add(*x));
    let total: u128 = b.iter().fold(0u128, |a, x| a.saturating_add(*x));
    let by_weight = total - total / 3; // two thirds of the weight, rounded up
    by_count.min(by_weight)
}

/// Which vaults a change of the bonded set retired and formed, by id: the custody lanes re-form exactly the formed
/// ones (a new wallet, the retired one's coins moved to it) and leave the others alone.
#[must_use]
pub fn diff(before: &[Vec<[u8; 32]>], after: &[Vec<[u8; 32]>]) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    let b: std::collections::BTreeSet<[u8; 32]> = before.iter().map(|v| vault_id(v)).collect();
    let a: std::collections::BTreeSet<[u8; 32]> = after.iter().map(|v| vault_id(v)).collect();
    (b.difference(&a).copied().collect(), a.difference(&b).copied().collect())
}

/// The invariants a table [`form`] returns holds — `Ok(())`, or the first one broken. Pins call it; nothing in
/// production reads it.
pub fn check(vaults: &[Vec<[u8; 32]>]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for (i, v) in vaults.iter().enumerate() {
        if v.is_empty() || v.len() > VAULT_MAX {
            return Err(format!("vault {i} holds {} member(s)", v.len()));
        }
        if vaults.len() > 1 && v.len() < VAULT_MIN {
            return Err(format!("vault {i} of {} holds {} member(s), under the minimum {VAULT_MIN}", vaults.len(), v.len()));
        }
        if v.windows(2).any(|w| w[0] >= w[1]) {
            return Err(format!("vault {i} is not sorted, or names a member twice"));
        }
        for m in v {
            if !seen.insert(*m) {
                return Err(format!("a custodian sits in two vaults (the second is vault {i})"));
            }
        }
    }
    Ok(())
}

// ───────────────────────────── THE ROTATION (spec §3f R5, §3f.2): SEATS MIX ON A SCHEDULE THE CHAIN DERIVES ─────────────────────────────
// A vault whose members never change is a vault a patient coalition can come to hold. So once per period each vault
// swaps [`MIX`] of its custodians with a partner vault the chain draws; both then take the key of their new member sets
// (the key lane's own rule: a key that names a custodian seated elsewhere is replaced at once) and their coins follow
// (the sweep lanes). These are the pure rules — who is due, who pairs with whom, which seats swap — shared by the node's
// fold step and by the lifecycle model (`models/custody-lifecycle`, which compiles this file by path), so the rule the
// model proves is the rule the node runs. Time here is whatever monotone measure the caller folds in: the node passes
// blue scores, the model days.
// BORROWED: THORChain's churn (a few nodes rotate between vaults on a schedule, the rest stay); Ethereum's committee
// shuffling (membership redrawn from chain randomness the members do not choose).

/// Custodians a vault swaps with its partner in one rotation.
pub const MIX: usize = 2;
/// Rotation days in one period: a vault's own day is its index modulo this, and at most one pair per this many seated
/// vaults mixes on any day.
pub const ROTATION_DAYS: u64 = 7;

/// One seated vault as the rotation rule sees it at a fold step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultTurn {
    pub vault: usize,
    /// when it last mixed (0: never)
    pub mixed: u64,
    /// may it mix now: its key is its members', its last re-key's coins are home (no replaced key alive), no merge is due
    pub settled: bool,
}

/// Is a vault that last mixed at `mixed` due at `now`? One `period` after its last mix; a vault that never mixed, on
/// its own day of the first period (its index modulo [`ROTATION_DAYS`]; the seventh day for a multiple of it).
#[must_use]
pub fn rotation_due(vault: usize, mixed: u64, now: u64, period: u64) -> bool {
    let day = (period / ROTATION_DAYS).max(1);
    if mixed == 0 {
        let own = match vault as u64 % ROTATION_DAYS {
            0 => ROTATION_DAYS,
            r => r,
        };
        now >= own.saturating_mul(day)
    } else {
        now >= mixed.saturating_add(period)
    }
}

/// THE PAIRS THAT MIX AT ONE FOLD STEP, as `(initiator, partner)`. A due, settled vault — the longest since its last
/// mix first, the lower index among equals — takes a partner drawn under `entropy` among the settled, RESTED vaults
/// (never mixed, or last mixed at least half a period ago) not already paired at this step; both are then marked mixed
/// by the caller. So a vault mixes at most twice in a period — once on its own turn, once as a partner — and each mix
/// is one re-key and one sweep for it. A pair is taken only while fewer than
/// `2·⌈vaults / ROTATION_DAYS⌉` vaults were marked on the current day (`now / day`), so at most `⌈vaults / 7⌉` pairs
/// mix on any day whatever was overdue. A due vault that is not settled, or finds no settled partner, stays due.
/// SCALE: one pass over the seated vaults and one draw per pair; nothing is stored here.
#[must_use]
pub fn rotations(turns: &[VaultTurn], now: u64, period: u64, entropy: &[u8; 32]) -> Vec<(usize, usize)> {
    rotations_within(turns, now, period, entropy, 2 * turns.len().div_ceil(ROTATION_DAYS as usize))
}

/// [`rotations`] with the day's bound on marked vaults passed in. The rule's own bound is the one [`rotations`]
/// passes; the lifecycle model passes no bound to show what the bound is for (its calibration).
#[must_use]
pub fn rotations_within(turns: &[VaultTurn], now: u64, period: u64, entropy: &[u8; 32], cap: usize) -> Vec<(usize, usize)> {
    let day = (period / ROTATION_DAYS).max(1);
    let today = now / day;
    let mut marked = turns.iter().filter(|t| t.mixed != 0 && t.mixed / day == today).count();
    let mut due: Vec<&VaultTurn> = turns.iter().filter(|t| t.settled && rotation_due(t.vault, t.mixed, now, period)).collect();
    due.sort_by_key(|t| (t.mixed, t.vault));
    let mut used: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for t in due {
        if marked.saturating_add(2) > cap {
            break;
        }
        if used.contains(&t.vault) {
            continue;
        }
        // a partner is settled AND RESTED: it never mixed, or last mixed at least half a period ago — so being drawn as a
        // partner costs a vault at most one more re-key (and sweep) per half period, whatever the draws
        let rested = |u: &VaultTurn| u.mixed == 0 || now >= u.mixed.saturating_add(period / 2);
        let pool: Vec<usize> = turns.iter().filter(|u| u.settled && rested(u) && u.vault != t.vault && !used.contains(&u.vault)).map(|u| u.vault).collect();
        if pool.is_empty() {
            continue;
        }
        let partner = pool[draw(entropy, "MonerousD custody rotation partner v1", t.vault as u64, pool.len())];
        used.insert(t.vault);
        used.insert(partner);
        marked += 2;
        out.push((t.vault, partner));
    }
    out
}

/// THE SEATS ONE MIX SWAPS, as `(a seat of the initiator, a seat of the partner)`: [`MIX`] occupied seats of each vault
/// (fewer when a vault holds fewer), drawn under `entropy` without replacement. The custodians on each pair exchange
/// seats; no vault's size changes.
#[must_use]
pub fn mix_seats(initiator: &[u64], partner: &[u64], entropy: &[u8; 32]) -> Vec<(u64, u64)> {
    let n = MIX.min(initiator.len()).min(partner.len());
    let pick = |seats: &[u64], tag: &str| -> Vec<u64> {
        let mut pool = seats.to_vec();
        pool.sort_unstable();
        pool.dedup();
        (0..n as u64).map(|j| pool.remove(draw(entropy, tag, j, pool.len()))).collect()
    };
    pick(initiator, "MonerousD custody mix out v1").into_iter().zip(pick(partner, "MonerousD custody mix in v1")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> [u8; 32] {
        *blake3::hash(&n.to_le_bytes()).as_bytes()
    }

    /// `n` custodians, the i-th bonded i-th.
    fn seniors(n: u64) -> Vec<[u8; 32]> {
        (0..n).map(id).collect()
    }

    /// ⭐ SAFE AT SCALE — the sizes the pillar names: Monero's limit (16), the first size past it (17), and sets ten, a
    /// hundred and a thousand times larger; and each size from 1 to 600. At each: a custodian in exactly one vault, no
    /// vault over 16, none under 8 once there are two, and a quorum of at most 11 — a constant, whatever the bonded set.
    /// CALIBRATION: what stood on main for the same sets — ONE custody set of all n, whose Monero wallet needs n signers.
    #[test]
    fn safe_at_scale_a_bonded_set_of_any_size_is_cut_into_vaults_of_eight_to_sixteen() {
        let named = [1u64, 16, 17, 160, 1_600, 16_000];
        for n in (1u64..=600).chain(named) {
            let order = seniors(n);
            let t = form(&order);
            check(&t).unwrap_or_else(|e| panic!("⛔ n = {n}: {e}"));
            assert_eq!(t.iter().map(Vec::len).sum::<usize>() as u64, n, "the table holds exactly the bonded custodians");
            let sz: Vec<usize> = t.iter().map(Vec::len).collect();
            assert_eq!(sz, sizes(n as usize), "the table is cut where `sizes` says");
            if n <= VAULT_MAX as u64 {
                assert_eq!(sz, vec![n as usize], "up to {VAULT_MAX} custodians are ONE vault — the custody set as it was");
            } else {
                assert!(n as usize > VAULT_MAX, "CALIBRATION: at n = {n} the single custody set needed {n} Monero signers, past Monero's {VAULT_MAX}");
                assert!(sz.len() >= 2 && sz.iter().all(|s| (VAULT_MIN..=VAULT_MAX).contains(s)), "⛔ at n = {n} a vault is outside {VAULT_MIN}..={VAULT_MAX}: {sz:?}");
            }
            let most = sz.iter().map(|s| quorum(*s)).max().unwrap_or(0);
            assert!(most <= quorum(VAULT_MAX), "⛔⛔ at n = {n} a vault needs {most} signers — more than a full vault's {}", quorum(VAULT_MAX));
            for i in 0..n {
                assert!(vault_of(&t, &id(i)).is_some(), "⛔ custodian {i} of {n} is in no vault");
            }
            if named.contains(&n) {
                eprintln!("[vaults] n = {n}: {} vault(s), sizes {}..={}, the most signers one operation needs: {most}", sz.len(), sz.iter().min().unwrap_or(&0), sz.iter().max().unwrap_or(&0));
            }
        }
        assert_eq!(quorum(VAULT_MAX), 11, "a full vault signs with 11 of 16");
        assert_eq!(sizes(17), vec![9, 8], "the 17th custodian splits the one vault in two halves");
        assert_eq!(sizes(23), vec![12, 11]);
        assert_eq!(sizes(24), vec![16, 8]);
        assert_eq!(sizes(39), vec![16, 12, 11], "seven left over: the last full vault and they share evenly");
        assert_eq!(sizes(40), vec![16, 16, 8]);
    }

    /// THE TABLE IS A FUNCTION OF THE SET, AND A BOND EVENT MOVES ONLY WHAT IT MUST. For set sizes from 1 to 400:
    /// (1) a custodian that BONDS (the most junior) changes at most the last two vaults — the vaults before them are
    ///     byte for byte what they were;
    /// (2) a custodian that LEAVES changes no vault more than one place senior to its own (the vault just senior
    ///     changes only when the last two are re-shared; the first run of this pin claimed "none senior" and a leave
    ///     from the last vault of 24 refuted it: [16, 8] becomes [12, 11]);
    /// (3) another seniority order is another table (the function reads the order, nothing else).
    #[test]
    fn a_bond_changes_at_most_the_last_two_vaults_and_a_leave_changes_no_vault_senior_to_it() {
        let (mut most_formed_by_a_join, mut joins_that_split) = (0usize, 0usize);
        for n in 1u64..=400 {
            let before = form(&seniors(n));
            let after = form(&seniors(n + 1));
            let (retired, formed) = diff(&before, &after);
            assert!(retired.len() <= 2 && formed.len() <= 2, "⛔⛔ n = {n}: one bond retired {} and formed {} vault(s)", retired.len(), formed.len());
            let untouched = before.len().saturating_sub(2);
            assert_eq!(before[..untouched], after[..untouched], "⛔ n = {n}: a bond changed a vault senior to the last two");
            most_formed_by_a_join = most_formed_by_a_join.max(formed.len());
            joins_that_split += usize::from(after.len() > before.len());
            // (2) each member in turn leaves
            if n <= 120 {
                for gone in 0..n {
                    let rest: Vec<[u8; 32]> = (0..n).filter(|i| *i != gone).map(id).collect();
                    let left = form(&rest);
                    check(&left).unwrap_or_else(|e| panic!("⛔ n = {n}, custodian {gone} left: {e}"));
                    let home = vault_of(&before, &id(gone)).expect("the leaver sat in a vault");
                    let kept = home.saturating_sub(1);
                    assert_eq!(before[..kept], left[..kept], "⛔⛔ n = {n}: custodian {gone} left vault {home} and a vault more than one place senior to it changed");
                    if home + 1 < before.len() && before.len() == left.len() && before[before.len() - 1].len() > VAULT_MIN {
                        assert_eq!(before[..home], left[..home], "⛔ n = {n}: custodian {gone} left a middle vault with no re-share due, and the vault just senior changed");
                    }
                }
            }
        }
        assert_eq!(most_formed_by_a_join, 2, "CALIBRATION: some bond did split a vault in two");
        assert!(joins_that_split >= 20, "CALIBRATION: the walk crossed {joins_that_split} splits");
        let t = form(&seniors(50));
        assert_eq!(form(&seniors(50)), t, "the same order gives the same table");
        assert_ne!(form(&seniors(50).into_iter().rev().collect::<Vec<_>>()), t, "CALIBRATION: another seniority order is another table");
    }

    /// WHAT A VAULT MAY HOLD IS LESS THAN WHAT TAKING IT COSTS. For each vault size and a spread of unequal bonds: any
    /// quorum of the vault forfeits strictly more than the vault's cover, and one member raising its bond never lowers
    /// the cover. A vault of nobody covers nothing.
    #[test]
    fn a_vaults_cover_is_under_the_bond_of_its_cheapest_quorum() {
        assert_eq!(cover(&[]), 0);
        for size in 1usize..=VAULT_MAX {
            for seed in 0u64..40 {
                let bonds: Vec<u128> = (0..size)
                    .map(|i| 1 + u128::from(u64::from_le_bytes(blake3::hash(&[seed.to_le_bytes(), (i as u64).to_le_bytes()].concat()).as_bytes()[..8].try_into().expect("8 bytes")) % 1_000_000))
                    .collect();
                let c = cover(&bonds);
                let mut sorted = bonds.clone();
                sorted.sort_unstable();
                let cheapest: u128 = sorted.iter().take(quorum(size)).sum();
                assert!(c < cheapest, "⛔⛔ a vault of {size} may hold {c}, and its cheapest quorum forfeits only {cheapest}");
                assert!(c * 4 <= cheapest * 3, "the cover is at most three quarters of the cheapest quorum's bond");
                let mut raised = bonds.clone();
                raised[0] += 1_000_000;
                assert!(cover(&raised) >= c, "⛔ a member raised its bond and the vault's cover fell");
                // the forfeit is under BOTH ways a vault signs: its cheapest count quorum, and two thirds of its weight
                let total: u128 = bonds.iter().sum();
                let f = forfeit(&bonds);
                assert!(f <= cheapest && f * 3 <= total * 2 + 2, "⛔ a vault of {size} forfeits {f}: more than its cheapest count quorum ({cheapest}) or than two thirds of its weight ({total})");
                assert!(f == cheapest || f == total - total / 3, "the forfeit IS the smaller of the two");
                assert!(forfeit(&raised) >= f, "⛔ a member raised its bond and the vault's forfeit fell");
            }
        }
        // 16 equal bonds of 100: the cheapest eleven hold 1,100, two thirds of the weight is 1,067 — the smaller is what the
        // cheapest signing set forfeits, and the vault may hold three quarters of it. (Before the weight quorum was counted
        // this read 825, three quarters of the count quorum alone.)
        assert_eq!(forfeit(&[100; 16]), 1_067);
        assert_eq!(cover(&[100; 16]), 800);
        assert_eq!(forfeit(&[]), 0);
    }

    /// ⭐⭐ SAFE AT SCALE — SEATS: ONE VAULT CHANGES PER BOND EVENT, WHATEVER THE BONDED SET. Custodians seated in arrival
    /// order fill vaults of sixteen and a tail; at 16, 17, 160, 1,600 and 16,000 no vault passes sixteen and no operation
    /// needs more than eleven signers. Then, on a set of 1,600: a leave changes exactly its own vault (CALIBRATION: the
    /// seniority cut re-forms every junior vault for the same leave); the next bond takes the seat it freed — the
    /// lowest free one — and changes exactly that vault; a vault emptied of every member keeps its index, so the vaults
    /// above it keep theirs.
    #[test]
    fn safe_at_scale_a_bond_or_a_leave_changes_exactly_one_vault_whatever_the_bonded_set() {
        use std::collections::BTreeSet;
        let seated = |n: u64| -> Vec<(u64, [u8; 32])> { (0..n).map(|i| (i, id(i))).collect() };
        for n in [1u64, 15, 16, 17, 160, 1_600, 16_000] {
            let v = by_seats(&seated(n));
            assert_eq!(v.len() as u64, n.div_ceil(VAULT_MAX as u64), "{n} custodians seated in order fill ⌈n/16⌉ vaults");
            assert!(v.iter().all(|x| !x.is_empty() && x.len() <= VAULT_MAX), "⛔ {n}: a vault is empty or past sixteen");
            assert!(v[..v.len() - 1].iter().all(|x| x.len() == VAULT_MAX), "{n}: every vault but the last is full");
            assert!(v.iter().all(|x| quorum(x.len()) <= quorum(VAULT_MAX)), "⛔ {n}: an operation needs more than eleven signers");
            assert_eq!(v.iter().map(Vec::len).sum::<usize>() as u64, n, "{n}: every custodian sits in exactly one vault");
        }
        let changed = |a: &[Vec<[u8; 32]>], b: &[Vec<[u8; 32]>]| -> Vec<usize> { (0..a.len().max(b.len())).filter(|i| a.get(*i) != b.get(*i)).collect() };
        let mut seats = seated(1_600);
        let mut taken: BTreeSet<u64> = (0..1_600).collect();
        assert_eq!(lowest_free_seat(&taken), 1_600, "a full run of seats: the next bond opens the next seat");
        for leaver in [37u64, 0, 1_599, 800] {
            let before = by_seats(&seats);
            seats.retain(|(s, _)| *s != leaver);
            taken.remove(&leaver);
            let after = by_seats(&seats);
            assert_eq!(changed(&before, &after), vec![vault_of_seat(leaver)], "⛔ the leave from seat {leaver} changed a vault other than its own");
            // CALIBRATION: the seniority cut, for the same leave, re-forms every vault from the leaver's down
            let (sb, sa): (Vec<[u8; 32]>, Vec<[u8; 32]>) = (before.iter().flatten().copied().collect(), after.iter().flatten().copied().collect());
            let cut_changed = changed(&form(&sb), &form(&sa)).len();
            if leaver < 1_500 {
                assert!(cut_changed > 5, "CALIBRATION: the seniority cut changed only {cut_changed} vault(s) for a leave near the front");
            }
        }
        // the freed seats are taken lowest first, one vault per bond
        for (k, want) in [0u64, 37, 800, 1_599, 1_600].into_iter().enumerate() {
            let seat = lowest_free_seat(&taken);
            assert_eq!(seat, want, "⛔ the bond took seat {seat}, not the lowest free one ({want})");
            let before = by_seats(&seats);
            seats.push((seat, id(10_000 + k as u64)));
            taken.insert(seat);
            let after = by_seats(&seats);
            assert_eq!(changed(&before, &after), vec![vault_of_seat(seat)], "⛔ the bond on seat {seat} changed a vault other than its own");
        }
        // a vault that lost every member keeps its index: the vaults above it keep theirs
        let mut two = seated(48);
        let top_before = by_seats(&two)[2].clone();
        two.retain(|(s, _)| vault_of_seat(*s) != 1);
        let v = by_seats(&two);
        assert_eq!(v.len(), 3, "an emptied vault's index stands");
        assert!(v[1].is_empty() && v[2] == top_before, "⛔ emptying vault 1 moved vault 2's members");
        assert_eq!(by_seats(&[]), Vec::<Vec<[u8; 32]>>::new());
    }

    /// ⛔⛔ SAFE AT SCALE / AI RESISTANT — THE SEAT DRAW: A RUN OF FRESH BONDS IS NEVER MORE THAN HALF OF ANY VAULT.
    /// CALIBRATION (the rule the draw replaces): sixteen custodians hold one vault; sixteen fresh bonds in a row under
    /// lowest-free-seat own the whole second vault — its quorum and its coins. Under the draw, from the same start and
    /// for every one of 64 chain randomness values, the same sixteen fresh bonds are exactly half of each vault, and no
    /// vault ever held fewer than eight older members when a newcomer joined it. Then 4,000 bonds and leaves at random:
    /// every bond changes exactly one vault or, on a split, exactly two; no vault passes sixteen; a newcomer never joins
    /// a vault of fewer than eight while a vault of eight exists; a split moves exactly eight members out of a full
    /// vault into an empty index; and the same seats with the same randomness always give the same seating.
    #[test]
    fn safe_at_scale_a_run_of_fresh_bonds_is_never_more_than_half_of_any_vault() {
        use std::collections::{BTreeMap, BTreeSet};
        let occupancy = |taken: &BTreeSet<u64>| -> BTreeMap<usize, usize> {
            let mut m = BTreeMap::new();
            for s in taken {
                *m.entry(vault_of_seat(*s)).or_default() += 1;
            }
            m
        };
        let entropy = |a: u64, b: u64| -> [u8; 32] {
            let mut h = blake3::Hasher::new_derive_key("draw-pin");
            h.update(&a.to_le_bytes());
            h.update(&b.to_le_bytes());
            *h.finalize().as_bytes()
        };
        // CALIBRATION: lowest-free-seat hands sixteen bonds in a row a whole vault
        let mut taken: BTreeSet<u64> = (0..16).collect();
        let mut fresh: BTreeSet<u64> = BTreeSet::new();
        for _ in 0..16 {
            let s = lowest_free_seat(&taken);
            taken.insert(s);
            fresh.insert(s);
        }
        assert_eq!(fresh.iter().filter(|s| vault_of_seat(**s) == 1).count(), 16, "CALIBRATION: under lowest-free-seat sixteen fresh bonds in a row ARE vault 1");
        // THE DRAW, for 64 different randomness values
        for run in 0..64u64 {
            let mut seats: BTreeMap<u64, bool> = (0..16).map(|s| (s, false)).collect(); // seat → is it a fresh bond's
            for k in 0..16u64 {
                let taken: BTreeSet<u64> = seats.keys().copied().collect();
                let before = occupancy(&taken);
                let s = draw_seat(&taken, &entropy(run, k));
                for (old, new) in &s.moved {
                    let who = seats.remove(old).expect("a moved seat was held");
                    assert!(seats.insert(*new, who).is_none(), "⛔ a split moved a member onto a held seat");
                }
                let joined = vault_of_seat(s.seat);
                let older = seats.keys().filter(|x| vault_of_seat(**x) == joined).count();
                assert!(older >= VAULT_MIN, "⛔ run {run}: a fresh bond joined a vault holding only {older} members");
                assert!(seats.insert(s.seat, true).is_none(), "⛔ the draw gave a held seat");
                if k == 0 {
                    assert_eq!(s.moved.len(), VAULT_MIN, "the seventeenth bond splits the one full vault: eight members move");
                    assert_eq!(before.get(&0), Some(&VAULT_MAX));
                } else {
                    assert!(s.moved.is_empty(), "⛔ run {run}: a bond with room in a vault of eight split a vault");
                }
            }
            let taken: BTreeSet<u64> = seats.keys().copied().collect();
            let occ = occupancy(&taken);
            assert_eq!(occ.values().copied().collect::<Vec<_>>(), vec![16, 16], "thirty-two custodians are two full vaults");
            for v in occ.keys() {
                let fresh_here = seats.iter().filter(|(s, f)| vault_of_seat(**s) == *v && **f).count();
                assert_eq!(fresh_here, VAULT_MIN, "⛔ run {run}: sixteen fresh bonds in a row hold {fresh_here} of vault {v}'s sixteen seats — more (or fewer) than half");
            }
        }
        // 4,000 bonds and leaves at random
        let mut taken: BTreeSet<u64> = BTreeSet::new();
        let mut splits = 0usize;
        for ev in 0..4_000u64 {
            let e = entropy(1_000, ev);
            let leave = !taken.is_empty() && e[0] % 5 == 0;
            if leave {
                let all: Vec<u64> = taken.iter().copied().collect();
                taken.remove(&all[(u64::from_le_bytes(e[8..16].try_into().unwrap()) % all.len() as u64) as usize]);
                continue;
            }
            let before = occupancy(&taken);
            let s = draw_seat(&taken, &e);
            assert_eq!(s, draw_seat(&taken, &e), "the same seats and the same randomness give the same seating");
            assert!(!taken.contains(&s.seat) || s.moved.iter().any(|(old, _)| *old == s.seat), "⛔ event {ev}: the draw gave a held seat");
            let eight_exists = before.values().any(|c| *c >= VAULT_MIN);
            if s.moved.is_empty() {
                let joined = before.get(&vault_of_seat(s.seat)).copied().unwrap_or(0);
                assert!(joined < VAULT_MAX, "⛔ event {ev}: a seventeenth member");
                assert!(!eight_exists || joined >= VAULT_MIN, "⛔ event {ev}: a newcomer joined a vault of {joined} while a vault of eight exists");
            } else {
                splits += 1;
                assert_eq!(s.moved.len(), VAULT_MIN, "a split moves exactly eight");
                let (from, to) = (vault_of_seat(s.moved[0].0), vault_of_seat(s.moved[0].1));
                assert!(s.moved.iter().all(|(old, new)| vault_of_seat(*old) == from && vault_of_seat(*new) == to && taken.contains(old)), "⛔ event {ev}: a split moved seats of more than one vault");
                assert_eq!(before.get(&from), Some(&VAULT_MAX), "⛔ event {ev}: a vault that was not full was split");
                assert!(!before.contains_key(&to), "⛔ event {ev}: a split moved members into a vault that has members");
                assert!(before.values().all(|c| *c < VAULT_MIN || *c == VAULT_MAX), "⛔ event {ev}: a vault of eight with room existed and a vault was split anyway");
                for (old, new) in &s.moved {
                    taken.remove(old);
                    taken.insert(*new);
                }
                assert!([from, to].contains(&vault_of_seat(s.seat)), "the newcomer joins one of the two halves");
            }
            taken.insert(s.seat);
            let after = occupancy(&taken);
            let changed = before.keys().chain(after.keys()).collect::<BTreeSet<_>>().into_iter().filter(|v| before.get(*v) != after.get(*v)).count();
            assert_eq!(changed, if s.moved.is_empty() { 1 } else { 2 }, "⛔ event {ev}: {changed} vaults changed");
            assert!(after.values().all(|c| *c <= VAULT_MAX), "⛔ event {ev}: a vault passed sixteen");
        }
        assert!(splits > 10, "CALIBRATION: the walk split vaults ({splits} times)");
        assert_eq!(draw_seat(&BTreeSet::new(), &entropy(0, 0)), Seating { seat: 0, moved: Vec::new() }, "the first custodian takes seat 0");
    }

    /// A vault's id is its member set whatever the order named; `diff` names exactly the vaults that changed.
    #[test]
    fn a_vaults_id_is_its_member_set() {
        assert_eq!(vault_id(&[id(1), id(2), id(3)]), vault_id(&[id(3), id(1), id(2), id(1)]), "a vault's id is its member SET");
        assert_ne!(vault_id(&[id(1), id(2)]), vault_id(&[id(1), id(2), id(3)]), "one more member is another vault");
        let t = form(&seniors(40));
        assert_eq!(diff(&t, &t), (Vec::new(), Vec::new()), "the same table retires and forms nothing");
        assert!(form(&[]).is_empty() && sizes(0).is_empty(), "no custodians, no vault");
    }

    /// ⭐ R5 (spec §3f.2) — THE ROTATION'S RULES OVER EVERY DRAW A PRODUCER COULD GRIND: sets of 2 to 70 vaults in drawn
    /// states (a third never mixed, a quarter not settled), 300 block ids each. Whatever the id: a pair is two different
    /// SETTLED vaults and no vault is in two pairs at one step; every initiator was due; the vaults marked in one day
    /// never pass `2·⌈vaults/7⌉`; and a mix draws [`MIX`] seats a side, each from its own vault's occupied seats, none
    /// twice. CALIBRATION: with the day's bound lifted at least as many pair; an only-due vault that is not settled
    /// pairs with nobody, and the same vault settled does.
    // TWO-PARTY-REVIEWED: pure functions of their arguments — there is no endpoint here; the node's fold step is held to
    // them across two nodes in `node::vault_pins::safe_at_scale_a_due_vault_mixes_two_custodians_with_a_drawn_partner…`.
    #[test]
    fn safe_at_scale_a_rotation_pairs_only_settled_vaults_inside_the_days_bound_whatever_the_block_id() {
        use std::collections::BTreeSet;
        let entropy = |a: u64, b: u64| -> [u8; 32] { *blake3::hash(&[a.to_le_bytes(), b.to_le_bytes()].concat()).as_bytes() };
        let period = 700u64; // a rotation day of 100
        let day = period / ROTATION_DAYS;
        let (mut most, mut steps) = (0usize, 0u64);
        for n in [2usize, 3, 7, 8, 16, 64, 70] {
            for round in 0..300u64 {
                let e = entropy(n as u64, round);
                let now = 1_000 + u64::from(e[0]) * 50;
                let turns: Vec<VaultTurn> = (0..n)
                    .map(|v| {
                        let r = entropy(round << 8 | n as u64, v as u64);
                        let ago = u64::from(u16::from_le_bytes([r[1], r[2]])) % (2 * period);
                        VaultTurn { vault: v, mixed: if r[0] % 3 == 0 { 0 } else { now.saturating_sub(ago).max(1) }, settled: r[3] % 4 != 0 }
                    })
                    .collect();
                let marked_before = turns.iter().filter(|t| t.mixed != 0 && t.mixed / day == now / day).count();
                let cap = 2 * n.div_ceil(ROTATION_DAYS as usize);
                let pairs = rotations(&turns, now, period, &e);
                let mut seen = BTreeSet::new();
                for (v, p) in &pairs {
                    assert!(seen.insert(*v) && seen.insert(*p), "⛔ {n} vaults, round {round}: a vault mixes twice at one step");
                    assert!(turns[*v].settled && turns[*p].settled, "⛔ {n} vaults, round {round}: an unsettled vault was paired");
                    assert!(rotation_due(*v, turns[*v].mixed, now, period), "⛔ {n} vaults, round {round}: an initiator that was not due");
                    assert!(turns[*p].mixed == 0 || now >= turns[*p].mixed + period / 2, "⛔ {n} vaults, round {round}: a partner that mixed under half a period ago was drawn again");
                }
                assert!(
                    pairs.is_empty() || marked_before + 2 * pairs.len() <= cap,
                    "⛔ {n} vaults, round {round}: {} vaults marked in one day over a bound of {cap}",
                    marked_before + 2 * pairs.len()
                );
                assert!(rotations_within(&turns, now, period, &e, usize::MAX).len() >= pairs.len(), "CALIBRATION: lifting the bound never pairs fewer");
                most = most.max(pairs.len());
                steps += 1;
            }
        }
        assert!(most >= 2, "CALIBRATION: the draws paired vaults (at most {most} pairs at one of {steps} steps)");
        let lone = |settled: bool| vec![VaultTurn { vault: 1, mixed: 0, settled }, VaultTurn { vault: 2, mixed: 4_000, settled: true }];
        assert!(rotations(&lone(false), 5_050, period, &entropy(1, 1)).is_empty(), "⛔ a vault that is not settled mixed");
        assert_eq!(rotations(&lone(true), 5_050, period, &entropy(1, 1)), vec![(1, 2)], "CALIBRATION: the same vault, settled, mixes with the one settled partner");
        assert!(!rotation_due(2, 4_000, 4_699, period) && rotation_due(2, 4_000, 4_700, period), "a vault is due one period after its last mix");
        assert!(!rotation_due(9, 0, 199, period) && rotation_due(9, 0, 200, period) && !rotation_due(7, 0, 699, period) && rotation_due(7, 0, 700, period), "a vault that never mixed is due on its own day");
        for round in 0..500u64 {
            let e = entropy(0x5ea7, round);
            let a: Vec<u64> = (0..16u64).filter(|i| e[*i as usize] % 5 != 0).collect();
            let b: Vec<u64> = (16..32u64).filter(|i| e[*i as usize] % 3 != 0).collect();
            let pairs = mix_seats(&a, &b, &e);
            assert_eq!(pairs.len(), MIX.min(a.len()).min(b.len()), "a mix draws MIX seats a side, fewer only when a vault holds fewer");
            let (xs, ys): (BTreeSet<u64>, BTreeSet<u64>) = (pairs.iter().map(|p| p.0).collect(), pairs.iter().map(|p| p.1).collect());
            assert!(xs.len() == pairs.len() && ys.len() == pairs.len(), "⛔ round {round}: a seat was drawn twice");
            assert!(xs.iter().all(|s| a.contains(s)) && ys.iter().all(|s| b.contains(s)), "⛔ round {round}: a seat outside its own vault's occupied seats was drawn");
        }
    }
}
