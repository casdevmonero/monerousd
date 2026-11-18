// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The vault's pins (docs/GOODS-AND-SERVICES-LAYER-SPEC-20261109.md §9.1, §12 step 1).
//!
//! TWO-PARTY-REVIEWED: these are the CARRIER's own accept and refuse verdicts — the one prover a wallet calls and the
//! one verifier a node door calls, exercised on hostile rows built against the production verifier. The two-party
//! check (a buyer's wallet and a seller's wallet on two real nodes: the vault opened through one node is spent through
//! the other, and a second spend by the other party is refused by the set) is the vault's real-node check, spec §12
//! step 1, and is not claimed here.

use super::*;
use crate::poseidon2_compress::lanes_of;

const FEE: u64 = PROTOCOL_FEE_ATOMIC;
const W: u64 = 12_720_000_000; // the vault holds $127.20
const T: u64 = 500_000; // a chain hour in 2027
const NO_SECRET: VaultSecret = [0; LOCK_LANES];

struct Parties {
    /// The buyer.
    a: NoteOwner,
    /// The seller.
    b: NoteOwner,
    /// The buyer's handover code: lock 1's secret, the seller takes with it.
    k: VaultSecret,
    /// The seller's refund code: lock 2's secret, the buyer takes with it.
    r: VaultSecret,
    seed: Digest,
}

fn parties() -> Parties {
    Parties {
        a: NoteOwner::from_test_key(lanes_of(&[0xA11CE, 1, 2, 3])),
        b: NoteOwner::from_test_key(lanes_of(&[0xB0B, 4, 5, 6])),
        k: [0x4B, 7, 7, 7],
        r: [0x52, 8, 8, 8],
        seed: lanes_of(&[0x5EED, 3, 1, 4, 1, 5, 9, 2]),
    }
}

/// A purchase vault owned by `owner` (the default party) from hour `T`: the seller takes with `k`, the buyer with `r`.
fn vault(p: &Parties, owner: &NoteOwner) -> VaultNote {
    let o = owner_opening(&owner.spk(), &p.seed);
    VaultNote {
        owner_spk: owner.spk(),
        seed: p.seed,
        t_h: T,
        lock1: vault_lock(&p.b.spk(), &p.k, &o),
        lock2: vault_lock(&p.a.spk(), &p.r, &o),
    }
}

/// A spend of `value_in` held by `owner`: everything but the fee to output 0.
fn witness(owner: NoteOwner, value_in: u64, out0_opening: Digest) -> SpendValidityWitness {
    SpendValidityWitness {
        value_in,
        owner,
        value_out: value_in - FEE,
        fee: FEE,
        lc_blind: lanes_of(&[0xB11D, 6, 6, 6]),
        out0_value: value_in - FEE,
        out0_opening,
        out1_value: 0,
        out1_opening: lanes_of(&[0xC4A, 2, 2, 2]),
    }
}

/// The spend of a vault holding `W` by `party`: the SPENDER's own keys, the vault's seed.
fn vault_spend(p: &Parties, party: &NoteOwner) -> SpendValidityWitness {
    witness(NoteOwner { ask: party.ask, nk: party.nk, seed: p.seed }, W, lanes_of(&[0x0A7, 1, 1, 1]))
}

fn spending(v: VaultNote, branch: VaultBranch, secret: VaultSecret, clock_h: u64) -> NoteSpendExtras {
    NoteSpendExtras::spending_vault(v, branch, secret, clock_h)
}

/// The honest path: the production prover, then the production verifier at `verify_clock`.
fn honest(w: &SpendValidityWitness, x: &NoteSpendExtras, verify_clock: u64) -> Option<(bool, [Digest; 2], Digest, Digest)> {
    let d = test_clue_digest(1);
    let (carrier, cms, nf, lc, tag1) = prove_note_spend_bytes(w, x, d, w.lc_blind, 0)?;
    let ok = verify_note_spend_bytes(&carrier, cms[0], cms[1], nf, lc, d, tag1, FEE, verify_clock);
    Option::from((ok, cms, nf, tag1))
}

/// The production gate over a laid row's own publics.
fn gate_of(row: &[Fa4], cms: &[DigestF; 2], nf: &DigestF, lc: &DigestF, clock_h: u64, gamma: Ea4) -> SpendValidityGate {
    gate_tagged(row, cms, nf, lc, clock_h, gamma, &row_claim_tag(row))
}

/// The claim tag a row publishes: the prover's own reading (`published_claim_tag`); a row with no vault region (the
/// spend before the vault existed) publishes its claim block's output.
fn row_claim_tag(row: &[Fa4]) -> DigestF {
    if row.len() > spend_validity_row_width() {
        published_claim_tag(row, spend_validity_row_width(), SV_TAIL + SV_TAIL_IN_BLK)
    } else {
        core::array::from_fn(|c| row[SV_CLAIM_BLK + crate::pow_pq_air::PERM_OUT + c])
    }
}

/// The production gate over a laid row's publics, with the claim tag the caller SAYS the spend publishes.
fn gate_tagged(row: &[Fa4], cms: &[DigestF; 2], nf: &DigestF, lc: &DigestF, clock_h: u64, gamma: Ea4, tag1_f: &DigestF) -> SpendValidityGate {
    let _ = row;
    let ea = |v: &DigestF| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| v[i].into()) };
    let mut g = SpendValidityGate {
        leaf_commit: ea(lc),
        gamma,
        out0_cm: ea(&cms[0]),
        out1_cm: ea(&cms[1]),
        nullifier: ea(nf),
        bond_amount: None,
        fee_amount: None,
        tag1: None,
        vault: None,
    };
    g.fee_amount = Option::from(fee_limbs(FEE));
    g.tag1 = Option::from(ea(tag1_f));
    g.vault = Option::from(clock_const(clock_h));
    g
}

fn carrier_cols(row: &[Fa4]) -> Vec<Vec<Fa4>> {
    (0..row.len()).map(|c| vec![row[c]; LIGHT_CARRIER_ROWS]).collect()
}

/// A HOSTILE row, proven against the production gate and judged by the production verifier. Its publics (the two
/// outputs, the spent tag, the cross-bind, the claim tag) are read from the row, so a refusal is the gate's.
fn forged_verifies(row: Vec<Fa4>, clock_h: u64) -> bool {
    let tag = row_claim_tag(&row);
    forged_verifies_publishing(row, clock_h, tag)
}

/// [`forged_verifies`] with the claim tag the hostile prover CHOOSES to publish.
fn forged_verifies_publishing(row: Vec<Fa4>, clock_h: u64, tag1_f: DigestF) -> bool {
    let cell = |at: usize| -> DigestF { core::array::from_fn(|c| row[at + c]) };
    let out_cm = |j: usize| cell(SV_OB + j * SV_OUT_SLOT + 1 + DIGEST_LANES + crate::pow_pq_air::P2_COLS);
    let (cms, nf) = ([out_cm(0), out_cm(1)], cell(SV_NF));
    let lc = cell(SV_CB2 + crate::pow_pq_air::PERM_OUT);
    let d = test_clue_digest(1);
    let cols = carrier_cols(&row);
    let make = move |g: Ea4| gate_tagged(&row, &cms, &nf, &lc, clock_h, g, &tag1_f);
    let bind = note_spend_public_bind(&cms, &nf, &lc, &to_f(&d), &tag1_f, clock_h);
    let Some(bytes) = crate::committed_air::prove_air_blinded_bytes(cols, make, &bind) else {
        return false;
    };
    verify_note_spend_bytes(&bytes, to_u64(&cms[0]), to_u64(&cms[1]), to_u64(&nf), to_u64(&lc), d, to_u64(&tag1_f), FEE, clock_h)
}

/// A row laid exactly as `x` says, with NO honest-prover check: what a lying prover lays.
fn lying_row(w: &SpendValidityWitness, x: &NoteSpendExtras) -> Vec<Fa4> {
    note_spend_row_as_said(w, x, w.lc_blind, 0).expect("a row is laid").0
}

fn leaf_of(row: &[Fa4]) -> Digest {
    use p3_field::PrimeField64;
    core::array::from_fn(|c| row[SV_LEAF + c].as_canonical_u64())
}

/// Re-lay the claim block over `(left, key)`, as a prover choosing its own claim would.
fn relay_claim(row: &mut [Fa4], left: &Digest, key: &Digest) {
    row[SV_CLAIM_KEY..SV_CLAIM_KEY + DIGEST_LANES].copy_from_slice(&to_f(key));
    crate::pow_pq_air::lay_perm_row_flat(row, SV_CLAIM_BLK, pose_state(&to_f(left), &to_f(key)));
}

/// Swap another party's keys into the owner block (its `spk` compression re-laid), leaving every other cell.
fn swap_spender(row: &mut [Fa4], party: &NoteOwner) {
    let (ask, nk) = (to_f(&party.ask), to_f(&party.nk));
    row[SV_OWNER + OWN_ASK..SV_OWNER + OWN_ASK + DIGEST_LANES].copy_from_slice(&ask);
    row[SV_OWNER + OWN_NK..SV_OWNER + OWN_NK + DIGEST_LANES].copy_from_slice(&nk);
    crate::pow_pq_air::lay_perm_row_flat(row, SV_OWNER + OWN_SPK_BLK, pose_state(&ask, &nk));
}

#[test]
fn a_payment_verifies_only_under_the_clock_it_was_proven_against() {
    let p = parties();
    let w = witness(p.a, 5_000_000 + FEE, lanes_of(&[1, 1, 1, 1]));
    assert!(honest(&w, &NoteSpendExtras::plain(T), T).expect("proves").0, "an ordinary payment proves and verifies");
    assert!(!honest(&w, &NoteSpendExtras::plain(T), T + 1).expect("proves").0, "⛔ a carrier verified under another clock");
    assert!(!honest(&w, &NoteSpendExtras::plain(T), 0).expect("proves").0, "⛔ a carrier verified under clock 0");
    // the old entry points are this same carrier at clock 0
    let d = test_clue_digest(1);
    let (carrier, cms, nf, lc, tag1) = prove_spend_validity_carrier_claiming_bytes(&w, d, w.lc_blind, 0).expect("proves");
    assert!(verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, lc, d, tag1, FEE));
    assert!(!verify_note_spend_bytes(&carrier, cms[0], cms[1], nf, lc, d, tag1, FEE, T));
    // a clock past the range an hour count holds has no carrier
    assert!(prove_note_spend_bytes(&w, &NoteSpendExtras::plain(1 << HOUR_BITS), d, w.lc_blind, 0).is_none());
    // a payment's publics are what they were before the vault existed: same commitments, same spent tag, same claim
    let (_, plain_cms, plain_nf, _) = spend_validity_row(&w).expect("the plain row lays");
    assert_eq!((to_u64(&plain_cms[0]), to_u64(&plain_cms[1]), to_u64(&plain_nf)), (cms[0], cms[1], nf));
    assert_eq!(cms[0], asset_note_cm(w.out0_value, USDM_ASSET_TAG, w.out0_opening));
    assert_eq!(tag1, ordinary_claim_tag(w.lc_blind));
}

#[test]
fn a_vault_is_made_by_one_spend_and_taken_by_either_lock_or_the_clock_under_one_spent_tag() {
    let p = parties();
    let v = vault(&p, &p.a); // the buyer is the default party: an undelivered purchase comes back at T
    // the buyer's ordinary note pays W into the vault: output 0 carries the vault's lanes and opening
    let make = witness(p.a, W + FEE, v.opening());
    let (ok, cms, ..) = honest(&make, &NoteSpendExtras::opening_vault(&v, T - 5), T - 5).expect("proves");
    assert!(ok, "the spend that creates a vault verifies");
    let vault_cm = v.note_cm(W);
    assert_eq!(cms[0], vault_cm, "the published output IS the vault note");
    assert_ne!(cms[0], asset_note_cm(W, USDM_ASSET_TAG, v.opening()), "and is not an ordinary note of its owner");

    // lock 1: the seller, with the buyer's code, before T
    let rel = spending(v, VaultBranch::Lock1, p.k, T - 1);
    assert_eq!(note_spend_input_leaf(&vault_spend(&p, &p.b), &rel), Option::from(vault_cm), "the spend opens exactly the note that was made");
    let (ok, _, nf_release, tag_release) = honest(&vault_spend(&p, &p.b), &rel, T - 1).expect("proves");
    assert!(ok, "the seller's release verifies");
    assert_eq!(nf_release, v.spent_tag(W), "the spent tag is the one both parties compute beforehand");
    assert_eq!(tag_release[..LOCK_LANES], v.lock1, "the claim tag the release publishes IS lock 1");
    // lock 2: the buyer, with the seller's code
    let (ok, _, nf_refund, tag_refund) = honest(&vault_spend(&p, &p.a), &spending(v, VaultBranch::Lock2, p.r, T - 1), T - 1).expect("proves");
    assert!(ok, "the buyer's refund verifies");
    assert_eq!(tag_refund[..LOCK_LANES], v.lock2);
    // clock: the owner (the buyer here), at T
    let (ok, _, nf_clock, _) = honest(&vault_spend(&p, &p.a), &spending(v, VaultBranch::Clock, NO_SECRET, T), T).expect("proves");
    assert!(ok, "the owner takes the vault at T");
    assert_eq!(nf_release, nf_refund, "⛔ the two locks must lay ONE spent tag, or both spends would land");
    assert_eq!(nf_release, nf_clock, "⛔ the clock branch must lay the same spent tag");
    // the same purchase with the SELLER as default party: a return window that ran out, a subscription period begun
    let vb = vault(&p, &p.b);
    let (ok, ..) = honest(&vault_spend(&p, &p.b), &spending(vb, VaultBranch::Clock, NO_SECRET, T + 9), T + 9).expect("proves");
    assert!(ok, "the seller takes a vault it owns, after T");
    assert_ne!(vb.note_cm(W), vault_cm, "the default party is part of what the vault commits to");
    assert_ne!(VaultNote { t_h: T + 1, ..v }.note_cm(W), vault_cm, "and so is its time");
    assert_ne!(VaultNote { lock1: NO_LOCK, ..v }.note_cm(W), vault_cm, "and each lock");
    assert_ne!(VaultNote { lock2: NO_LOCK, ..v }.note_cm(W), vault_cm);
    assert_ne!(v.note_cm(W + 1), vault_cm, "and its amount");
}

#[test]
fn the_honest_prover_refuses_what_the_gate_refuses() {
    let p = parties();
    let v = vault(&p, &p.a);
    let d = test_clue_digest(1);
    let no = |w: SpendValidityWitness, x: NoteSpendExtras| prove_note_spend_bytes(&w, &x, d, w.lc_blind, 0).is_none();
    assert!(no(vault_spend(&p, &p.a), spending(v, VaultBranch::Clock, NO_SECRET, T - 1)), "the clock branch before T");
    assert!(no(vault_spend(&p, &p.b), spending(v, VaultBranch::Clock, NO_SECRET, T)), "the clock branch by the party that is not the owner");
    assert!(no(vault_spend(&p, &p.a), spending(v, VaultBranch::Lock1, p.k, T)), "lock 1 by the buyer, who knows its secret");
    assert!(no(vault_spend(&p, &p.b), spending(v, VaultBranch::Lock2, p.r, T)), "lock 2 by the seller, who knows its secret");
    assert!(no(vault_spend(&p, &p.b), spending(v, VaultBranch::Lock1, p.r, T)), "lock 1 with the wrong secret");
    assert!(no(vault_spend(&p, &p.b), spending(VaultNote { lock1: NO_LOCK, ..v }, VaultBranch::Lock1, p.k, T)), "a lock that is not set");
    // an output named a vault must carry that vault's opening
    let make = witness(p.a, W + FEE, lanes_of(&[3, 3, 3, 3]));
    assert!(no(make, NoteSpendExtras::opening_vault(&v, T)));
}

/// Every lie is laid as a row — the honest row of the vault itself with one thing false — and proven against the
/// production gate; the production verifier must refuse it.
#[test]
fn every_lie_about_a_vault_is_refused_by_the_gate() {
    let p = parties();
    let v = vault(&p, &p.a);
    let vault_cm = v.note_cm(W);
    let at = T + 1;
    let base = spend_validity_row_width();
    let in_inner = SV_TAIL + SV_TAIL_IN_BLK;
    let release = spending(v, VaultBranch::Lock1, p.k, at);
    // the calibration: the same machinery accepts the truth, so a refusal below is the gate's
    let row = lying_row(&vault_spend(&p, &p.b), &release);
    assert_eq!(leaf_of(&row), vault_cm, "the release row lays the vault note itself");
    assert!(forged_verifies(row, at), "the honest release row verifies through the hostile-row path");

    let tampered = |name: &str, party: &NoteOwner, x: &NoteSpendExtras, clock_h: u64, edit: &dyn Fn(&mut Vec<Fa4>)| {
        let mut row = lying_row(&vault_spend(&p, party), x);
        assert_eq!(leaf_of(&row), vault_cm, "{name}: the lie is told about the vault itself");
        edit(&mut row);
        assert!(!forged_verifies(row, clock_h), "⛔ {name}: verified");
    };
    let o = v.opening();
    // THE BUYER KNOWS THE HANDOVER CODE. It swaps its own keys into the seller's release row …
    tampered("lock 1 taken by the buyer, the claim still naming the seller", &p.b, &release, at, &|row| swap_spender(row, &p.a));
    // … or lays the claim under its own key, which is then not the lock
    tampered("lock 1 taken by the buyer under its own claim", &p.b, &release, at, &|row| {
        swap_spender(row, &p.a);
        relay_claim(row, &lock_claim_left(&p.a.spk(), false), &lock_claim_key(&p.k, &o));
    });
    tampered("lock 1 with a secret that is not its own", &p.b, &release, at, &|row| {
        relay_claim(row, &lock_claim_left(&p.b.spk(), false), &lock_claim_key(&p.r, &o));
    });
    tampered("lock 1 under an ordinary claim", &p.b, &release, at, &|row| {
        relay_claim(row, &lanes_of(&[crate::slot_ledger::SLOT_CLAIM_DOMAIN]), &lock_claim_key(&p.k, &o));
    });
    tampered("lock 1's claim read as lock 2", &p.b, &release, at, &|row| {
        row[base + VB_SEL] = Fa4::ZERO;
        row[base + VB_SEL + 1] = Fa4::ONE;
    });
    tampered("two branches at once", &p.b, &release, at, &|row| row[base + VB_SEL + 2] = Fa4::ONE);
    tampered("a branch bit that is not a bit", &p.b, &release, at, &|row| row[base + VB_SEL] = Fa4::TWO);
    tampered("no branch over a vault note", &p.b, &release, at, &|row| row[base + VB_SEL] = Fa4::ZERO);
    // THE SELLER TAKES THE BUYER'S CLOCK BRANCH: the owner's clock row with the seller's keys swapped in
    let clock = spending(v, VaultBranch::Clock, NO_SECRET, at);
    tampered("the clock branch by the party that is not the owner", &p.a, &clock, at, &|row| swap_spender(row, &p.b));
    // … or lays the clock bit over its own lock row (whose opening is not its own)
    tampered("the clock bit over a lock row", &p.b, &release, at, &|row| {
        row[base + VB_SEL] = Fa4::ZERO;
        row[base + VB_SEL + 2] = Fa4::ONE;
        for k in 0..HOUR_BITS {
            row[base + VB_CLOCK + LE_A_BITS + k] = Fa4::from_u64((T >> k) & 1);
            row[base + VB_CLOCK + LE_SLACK_BITS + k] = Fa4::from_u64(((at - T) >> k) & 1);
        }
    });
    // THE OWNER TAKES ITS VAULT BEFORE ITS TIME: the clock row laid at T, judged an hour early …
    let at_t = spending(v, VaultBranch::Clock, NO_SECRET, T);
    assert!(forged_verifies(lying_row(&vault_spend(&p, &p.a), &at_t), T), "CALIBRATION: the clock row verifies at T");
    assert!(!forged_verifies(lying_row(&vault_spend(&p, &p.a), &at_t), T - 1), "⛔ the clock branch verified before the vault's time");
    // … with the compare re-laid for the earlier clock (T − 1 − T has no 22-bit slack; every slack bit set is as near as cells come) …
    tampered("a wrapped compare", &p.a, &at_t, T - 1, &|row| {
        for k in 0..HOUR_BITS {
            row[base + VB_CLOCK + LE_SLACK_BITS + k] = Fa4::ONE;
        }
    });
    // … with an earlier time laid in the compare than the note holds …
    tampered("an earlier time than the vault's", &p.a, &at_t, T - 1, &|row| {
        for k in 0..HOUR_BITS {
            row[base + VB_CLOCK + LE_A_BITS + k] = Fa4::from_u64(((T - 1) >> k) & 1);
            row[base + VB_CLOCK + LE_SLACK_BITS + k] = Fa4::ZERO;
        }
    });
    // … or through the PLAIN branch, as the ordinary note of its owner it otherwise is
    tampered("the owner on the plain branch", &p.a, &at_t, T, &|row| row[base + VB_SEL + 2] = Fa4::ZERO);
    tampered("the owner on the plain branch with the kind lane cleared", &p.a, &at_t, T, &|row| {
        row[base + VB_SEL + 2] = Fa4::ZERO;
        row[in_inner + NOTE_KIND_LANE] = Fa4::ZERO;
    });

    // ONE SECRET, TWO VAULTS: a second vault carries the FIRST vault's lock 1. The seller's claim for it is the first
    // vault's (its key holds the first vault's opening lanes), so it is not this vault's key.
    let p2 = Parties { seed: lanes_of(&[0x5EED, 9, 9, 9]), ..parties() };
    let v2 = VaultNote { lock1: v.lock1, ..vault(&p2, &p2.a) };
    let mut row = lying_row(&vault_spend(&p2, &p2.b), &spending(v2, VaultBranch::Lock1, p.k, at));
    assert_eq!(leaf_of(&row), v2.note_cm(W));
    relay_claim(&mut row, &lock_claim_left(&p.b.spk(), false), &lock_claim_key(&p.k, &o));
    assert!(!forged_verifies(row, at), "⛔ a lock opened by the claim of another vault");
}

#[test]
fn an_ordinary_note_has_no_lock_and_no_clock_branch_and_its_spent_tag_is_its_owners() {
    let p = parties();
    let base = spend_validity_row_width();
    let pay = witness(p.a, W, lanes_of(&[2, 2, 2, 2]));
    let plain = lying_row(&pay, &NoteSpendExtras::plain(T));
    assert!(forged_verifies(plain.clone(), T), "CALIBRATION: the plain row verifies through the hostile-row path");
    // a vault branch laid over an ordinary note: its kind and lock lanes are zero, so no branch fits it
    for bit in 0..VaultBranch::ALL.len() {
        let mut row = plain.clone();
        row[base + VB_SEL + bit] = Fa4::ONE;
        assert!(!forged_verifies(row, T), "⛔ vault branch {bit} opened an ordinary note");
    }
    // a payment's spent tag is keyed by its owner's `nk`; a vault's by its opening. Keying a payment by its opening —
    // what its SENDER, who knows the opening, could compute — is refused.
    let o: DigestF = core::array::from_fn(|c| plain[SV_SK + c]);
    let leaf: DigestF = core::array::from_fn(|c| plain[SV_LEAF + c]);
    let mut forged = plain.clone();
    let sender_nf = fill_pose_round(&mut forged, &o, &leaf, SV_NFH_BLK, SV_NF);
    // the cross-bind re-laid over the forged tag, so the ONLY false cell set is the tag's key
    let inner = fill_pose_round(&mut forged, &leaf, &sender_nf, SV_CB, SV_CB2);
    let blind: DigestF = core::array::from_fn(|c| forged[SV_BLIND + c]);
    crate::pow_pq_air::lay_perm_row_flat(&mut forged, SV_CB2, pose_state(&inner, &blind));
    assert!(!forged_verifies(forged, T), "⛔ a payment's spent tag was keyed by its opening");
    // an input with a lock lane set but no branch: not an ordinary note, and the plain branch refuses it
    for at in [SV_TAIL + SV_TAIL_IN_BLK + SC_LIMBS, SV_NOH_BLK + SC_LIMBS] {
        let mut row = plain.clone();
        row[at] = Fa4::ONE;
        assert!(!forged_verifies(row, T), "⛔ the plain branch opened a note with a lock lane set");
    }
}

/// A seller's content key: four lanes, one of them the field's largest, so the lane sum wraps.
const CONTENT_KEY: VaultSecret = [0x00C0_FFEE, 0x7F00_0000, 3, 0x1234_5678];
/// The listing's salt.
const SALT: ListingSalt = [0x5A17, 11, 12, 13];

/// A DOWNLOAD's vault: the buyer's from `T` (an undelivered download comes back by the clock), both lock slots the
/// SELLER'S eight-lane delivery lock over its own content key. The lock is the listing's: the same for every buyer.
fn download_vault(p: &Parties, key: &VaultSecret) -> VaultNote {
    let [lock1, lock2] = delivery_locks(&p.b.spk(), key, &SALT);
    VaultNote { lock1, lock2, ..vault(p, &p.a) }
}

fn d_of() -> Digest {
    test_clue_digest(1)
}

#[test]
fn a_delivery_claim_pays_the_seller_and_hands_the_buyer_the_key_in_the_same_spend() {
    let p = parties();
    let v = download_vault(&p, &CONTENT_KEY);
    let at = T - 1;
    let w = vault_spend(&p, &p.b);
    let (ok, _, nf, tag) = honest(&w, &NoteSpendExtras::delivering(v, CONTENT_KEY, SALT, at), at).expect("proves");
    assert!(ok, "the seller's delivery claim verifies");
    assert_eq!(nf, v.spent_tag(W), "under the vault's one spent tag: the buyer finds this spend by it");
    assert_eq!(tag, delivery_claim_tag(&v, &CONTENT_KEY), "the published tag is the one the seller's wallet states beforehand");
    // THE BUYER, holding the vault, reads the key out of the published tag and checks it against the lock it funded
    let got = delivered_secret(&tag, &v).expect("the tag is this vault's claim");
    assert_eq!(got, CONTENT_KEY, "the buyer has the key the moment the seller is paid");
    assert_eq!(delivery_locks(&p.b.spk(), &got, &SALT), [v.lock1, v.lock2], "and it IS the key of the lock the buyer funded");
    // the lock is the listing's whole claim hash, the same for every buyer; the published tag carries none of it
    let hash = delivery_claim_hash(&p.b.spk(), &CONTENT_KEY, &SALT);
    assert_eq!((&hash[..LOCK_LANES], &hash[LOCK_LANES..]), (&v.lock1[..], &v.lock2[..]));
    assert!((0..DIGEST_LANES).all(|c| tag[c] != hash[c]), "nothing on the chain names the listing");
    // ANOTHER BUYER of the same listing: another vault, the same lock, the same key, another tag
    let p2 = Parties { seed: lanes_of(&[0x5EED, 9, 9, 9]), a: NoteOwner::from_test_key(lanes_of(&[0xCA401, 7, 7, 7])), ..parties() };
    let v2 = download_vault(&p2, &CONTENT_KEY);
    assert_eq!([v2.lock1, v2.lock2], [v.lock1, v.lock2], "one listing, one lock");
    let (ok, _, nf2, tag2) = honest(&vault_spend(&p2, &p2.b), &NoteSpendExtras::delivering(v2, CONTENT_KEY, SALT, at), at).expect("proves");
    assert!(ok && nf2 != nf);
    assert!((0..DIGEST_LANES).all(|c| tag2[c] != tag[c]), "two sales of one listing share no lane of their tags");
    assert_eq!(delivered_secret(&tag2, &v2), Some(CONTENT_KEY));
    // the first buyer, who knows the key and the lock, does not recognise the second sale's tag as a claim of its own
    // vault, and reading it as one gives no key
    assert!(delivered_secret(&tag2, &v).is_none());
    assert!(delivered_secret(&tag, &v2).is_none());
    // the honest prover lays neither wrong reading: a delivery lock is not opened by an ordinary claim, an ordinary
    // lock is not opened by a delivery claim, and a delivery claim names its listing's own salt
    let d = d_of();
    assert!(prove_note_spend_bytes(&w, &spending(v, VaultBranch::Lock1, CONTENT_KEY, at), d, w.lc_blind, 0).is_none(), "⛔ a delivery lock was opened without publishing its key");
    let plain_lock = vault(&p, &p.a);
    assert!(prove_note_spend_bytes(&w, &NoteSpendExtras::delivering(plain_lock, p.k, SALT, at), d, w.lc_blind, 0).is_none(), "⛔ an ordinary lock was opened as a delivery");
    assert!(prove_note_spend_bytes(&w, &NoteSpendExtras::delivering(v, CONTENT_KEY, [1, 2, 3, 4], at), d, w.lc_blind, 0).is_none(), "⛔ a delivery claim under another listing's salt");
    // the buyer's way back is the clock, under the same spent tag (so one of the two lands); no code opens lock 2
    let (ok, _, nf_clock, _) = honest(&vault_spend(&p, &p.a), &spending(v, VaultBranch::Clock, NO_SECRET, T), T).expect("proves");
    assert!(ok && nf_clock == nf, "an undelivered download comes back at T under the vault's one spent tag");
    assert!(prove_note_spend_bytes(&vault_spend(&p, &p.a), &spending(v, VaultBranch::Lock2, p.r, at), d, w.lc_blind, 0).is_none(), "a delivery vault has no refund-code branch");
}

/// THE SELLER MUST NOT BE PAID WITHOUT HANDING OVER THE KEY. Each lie is the honest delivery row with one thing
/// false, proven against the production gate and judged by the production verifier.
#[test]
fn a_seller_cannot_take_a_delivery_vault_without_publishing_its_key() {
    let p = parties();
    let v = download_vault(&p, &CONTENT_KEY);
    let (o, at) = (v.opening(), T - 1);
    let in_inner = SV_TAIL + SV_TAIL_IN_BLK;
    let w = vault_spend(&p, &p.b);
    let x = NoteSpendExtras::delivering(v, CONTENT_KEY, SALT, at);
    let honest_row = lying_row(&w, &x);
    assert_eq!(leaf_of(&honest_row), v.note_cm(W), "the row lays the download's vault");
    let honest_tag = row_claim_tag(&honest_row);
    assert_eq!(to_u64(&honest_tag), delivery_claim_tag(&v, &CONTENT_KEY));
    assert!(forged_verifies(honest_row.clone(), at), "CALIBRATION: the honest delivery row verifies through the hostile-row path");
    let (left, key) = delivery_claim_inputs(&p.b.spk(), &CONTENT_KEY, &SALT);

    // 1. the seller publishes the claim's HASH (what an ordinary lock publishes) and keeps the key
    let hash: DigestF = core::array::from_fn(|c| honest_row[SV_CLAIM_BLK + crate::pow_pq_air::PERM_OUT + c]);
    assert!(!forged_verifies_publishing(honest_row.clone(), at, hash), "⛔ a delivery vault was taken with the key withheld");
    // 2. … or a tag differing in any one lane (a wrong key, or upper lanes that are not the vault's inner hash)
    for lane in 0..DIGEST_LANES {
        let mut t = honest_tag;
        t[lane] += Fa4::ONE;
        assert!(!forged_verifies_publishing(honest_row.clone(), at, t), "⛔ lane {lane} of the published tag is not welded");
    }
    // 3. the slot cell cleared (the tag then reads as the hash) with the claim block left as laid
    let mut row = honest_row.clone();
    row[SV_CLAIM_D] = Fa4::ZERO;
    assert!(!forged_verifies(row.clone(), at), "⛔ the slot cell is not welded to the claim's input");
    assert!(!forged_verifies_publishing(row, at, hash), "⛔ the slot cell is not welded to the claim's input");
    // 4. the claim re-laid as an ORDINARY lock claim over the same key (slot lane 0): its hash is not the delivery
    // lock, whichever upper key lanes it carries (the salt, or the vault's opening as an ordinary claim must)
    for upper in [key, lock_claim_key(&CONTENT_KEY, &o)] {
        let mut row = honest_row.clone();
        row[SV_CLAIM_D] = Fa4::ZERO;
        relay_claim(&mut row, &lock_claim_left(&p.b.spk(), false), &upper);
        assert!(!forged_verifies(row, at), "⛔ a delivery lock was opened by an ordinary claim");
    }
    // 5. the key cells changed after the block was laid (publishing a pad of the seller's choosing)
    for c in 0..DIGEST_LANES {
        let mut row = honest_row.clone();
        row[SV_CLAIM_KEY + c] += Fa4::ONE;
        assert!(!forged_verifies(row, at), "⛔ key cell {c} is not welded to the claim's input");
    }
    // 5b. the opening cells the pad reads, and the inner hash cells the upper lanes read, are the spent note's own
    for (name, cell) in [("opening", SV_SK), ("inner hash", in_inner + crate::pow_pq_air::PERM_OUT + LOCK_LANES)] {
        let mut row = honest_row.clone();
        row[cell] += Fa4::ONE;
        assert!(!forged_verifies(row, at), "⛔ the {name} cell the published tag reads is free");
    }
    // 6. a delivery claim under a key that is not the lock's, or under another salt
    let mut row = honest_row.clone();
    relay_claim(&mut row, &left, &delivery_claim_inputs(&p.b.spk(), &p.k, &SALT).1);
    assert!(!forged_verifies(row, at), "⛔ a delivery lock was opened with a key that is not its own");
    let mut row = honest_row.clone();
    relay_claim(&mut row, &left, &delivery_claim_inputs(&p.b.spk(), &CONTENT_KEY, &[1, 2, 3, 4]).1);
    assert!(!forged_verifies(row, at), "⛔ a delivery lock was opened under another salt");
    // 7. the buyer, who funded the vault, lays the seller's delivery row under its own keys
    let mut row = honest_row.clone();
    swap_spender(&mut row, &p.a);
    assert!(!forged_verifies(row, at), "⛔ a delivery lock was taken by a party it does not name");
    // 8. AN ORDINARY LOCK IS NOT A DELIVERY: the handover lock of a purchase, claimed with the slot cell set
    let plain = vault(&p, &p.a);
    let mut row = lying_row(&w, &spending(plain, VaultBranch::Lock1, p.k, at));
    assert!(forged_verifies(row.clone(), at), "CALIBRATION: the ordinary release verifies");
    row[SV_CLAIM_D] = Fa4::ONE;
    assert!(!forged_verifies(row.clone(), at), "⛔ an ordinary lock was claimed with the slot cell set");
    relay_claim(&mut row, &lock_claim_left(&p.b.spk(), true), &lock_claim_key(&p.k, &plain.opening()));
    assert!(!forged_verifies(row, at), "⛔ an ordinary lock was opened by a delivery claim");
    // 8a. AN ORDINARY CLAIM STILL NAMES ITS VAULT: its upper key lanes are the vault's opening, never free
    let mut row = lying_row(&w, &spending(plain, VaultBranch::Lock1, p.k, at));
    row[SV_CLAIM_KEY + LOCK_LANES] += Fa4::ONE;
    assert!(!forged_verifies(row, at), "⛔ an ordinary lock claim's upper key lanes are free");
    // 8b. TWO KEYS UNDER ONE LOCK (why the lock is eight lanes). A vault whose lock 1 is the delivery lock's first four
    // lanes but whose lock 2 is something else (here an ordinary refund lock) is not a delivery vault: its claim's
    // upper lanes are not its lock 2, so a seller cannot be paid through a four-lane half of the lock.
    let half = VaultNote { lock2: plain.lock2, ..v };
    let said = NoteSpendExtras::delivering(half, CONTENT_KEY, SALT, at);
    assert!(prove_note_spend_bytes(&w, &said, d_of(), w.lc_blind, 0).is_none(), "the honest prover lays no half lock");
    let row = lying_row(&w, &said);
    assert_eq!(leaf_of(&row), half.note_cm(W), "the lie is told about the half-locked vault itself");
    assert!(!forged_verifies(row, at), "⛔ a delivery claim opened a lock of four lanes");
    // 8c. the slot cell is a bit on the lock 1 branch, and 0 on the lock 2 branch
    let mut row = honest_row.clone();
    row[SV_CLAIM_D] = Fa4::TWO;
    assert!(!forged_verifies(row, at), "⛔ a slot cell that is not a bit");
    let refund = lying_row(&vault_spend(&p, &p.a), &spending(plain, VaultBranch::Lock2, p.r, at));
    assert!(forged_verifies(refund.clone(), at), "CALIBRATION: the ordinary refund verifies");
    let mut row = refund;
    row[SV_CLAIM_D] = Fa4::ONE;
    relay_claim(&mut row, &lock_claim_left(&p.a.spk(), true), &lock_claim_key(&p.r, &plain.opening()));
    assert!(!forged_verifies(row, at), "⛔ a delivery claim through lock 2");
    // 9. A PAYMENT'S CLAIM IS UNTOUCHED BY THE SLOT CELL: an ordinary spend claiming device slot 1 publishes its hash
    let pay = witness(p.a, 5_000_000 + FEE, lanes_of(&[1, 1, 1, 1]));
    let d = d_of();
    let (carrier, cms, nf, lc, tag1) = prove_note_spend_bytes(&pay, &NoteSpendExtras::plain(at), d, lanes_of(&[9, 9, 9, 9]), 1).expect("proves");
    assert!(verify_note_spend_bytes(&carrier, cms[0], cms[1], nf, lc, d, tag1, FEE, at));
    assert_eq!(tag1, poseidon_pair(lanes_of(&[crate::slot_ledger::SLOT_CLAIM_DOMAIN, 1]), lanes_of(&[9, 9, 9, 9])), "a slot claim's tag is its hash, as before the delivery lock existed");
}

fn census_cases(p: &Parties) -> Vec<(&'static str, SpendValidityWitness, NoteSpendExtras)> {
    let (v, vb) = (vault(p, &p.a), vault(p, &p.b));
    let pay = witness(p.a, 5_000_000 + FEE, lanes_of(&[1, 1, 1, 1]));
    let mut make = witness(p.a, W + FEE, v.opening());
    make.out1_opening = vb.opening();
    let mut both = NoteSpendExtras::opening_vault(&v, T);
    both.out_vaults[1] = Option::from(vb);
    vec![
        ("payment", pay, NoteSpendExtras::plain(T)),
        ("makes two vaults", make, both),
        ("lock 1", vault_spend(p, &p.b), spending(v, VaultBranch::Lock1, p.k, T)),
        ("lock 2", vault_spend(p, &p.a), spending(v, VaultBranch::Lock2, p.r, T)),
        ("clock", vault_spend(p, &p.a), spending(v, VaultBranch::Clock, NO_SECRET, T + 3)),
        ("lock 1 on the seller's own vault", vault_spend(p, &p.b), spending(vb, VaultBranch::Lock1, p.k, T)),
        ("delivery lock", vault_spend(p, &p.b), NoteSpendExtras::delivering(download_vault(p, &CONTENT_KEY), CONTENT_KEY, SALT, T)),
    ]
}

/// SOUND IS MEASURED: the three censuses (degree, free witness, decorative block) on the note-class gate over each
/// kind of row it proves — a payment, a spend that makes vaults, and a vault spent through each branch.
#[test]
fn the_note_class_gate_passes_the_three_censuses_on_every_kind_of_row() {
    let p = parties();
    for (name, w, x) in census_cases(&p) {
        let (row, cms, nf, lc) = note_spend_row(&w, &x, w.lc_blind, 0).unwrap_or_else(|| panic!("{name}: the honest row lays"));
        let g = gate_of(&row, &cms, &nf, &lc, x.clock_h, Ea4::from(Fa4::from_u64(0x7A17)));
        let oob = crate::air_zerocheck::OobLatch::new();
        let vals: Vec<Ea4> = row.iter().map(|v| Ea4::from(*v)).collect();
        let rs = g.residuals(&crate::air_zerocheck::Row::new(&vals, &oob));
        let bad: Vec<usize> = rs.iter().enumerate().filter(|(_, r)| **r != Ea4::ZERO).map(|(i, _)| i).collect();
        assert!(bad.is_empty(), "{name}: residual(s) {bad:?} of {} are non-zero on the honest row", rs.len());
        eprintln!("[vault-census] {name}: {} residuals, {} columns", rs.len(), row.len());
        let cols = carrier_cols(&row);
        let nvars = cols[0].len().trailing_zeros() as usize;
        crate::air_zerocheck::debug_degree_census(&cols, &g, nvars, true, &Some(Vec::new()));
        crate::air_zerocheck::debug_free_witness_census(&cols, &g, nvars, true, &Some(Vec::new()));
        crate::air_zerocheck::debug_decorative_block_census(&cols, &g, nvars, true, &Some(Vec::new()));
    }
}

/// THE MUTATION CENSUS's question, asked here of every residual of the note-class gate: on at least one kind of
/// honest row, some single-cell nudge must move it. A residual no nudge moves on any row is one a dropped
/// constraint could hide in.
#[test]
fn no_residual_of_the_note_class_gate_is_dead_across_the_rows_it_proves() {
    let p = parties();
    let oob = crate::air_zerocheck::OobLatch::new();
    let mut alive: Vec<bool> = Vec::new();
    for (_, w, x) in census_cases(&p) {
        let (row, cms, nf, lc) = note_spend_row(&w, &x, w.lc_blind, 0).expect("lays");
        let g = gate_of(&row, &cms, &nf, &lc, x.clock_h, Ea4::ONE);
        let vals: Vec<Ea4> = row.iter().map(|v| Ea4::from(*v)).collect();
        let base_rs = g.residuals(&crate::air_zerocheck::Row::new(&vals, &oob));
        alive.resize(base_rs.len(), false);
        for col in 0..vals.len() {
            for delta in [1u64, 0x9E37_79B9] {
                let mut v = vals.clone();
                v[col] += Ea4::from(Fa4::from_u64(delta));
                let rs = g.residuals(&crate::air_zerocheck::Row::new(&v, &oob));
                for (i, (a, b)) in rs.iter().zip(base_rs.iter()).enumerate() {
                    if a != b {
                        alive[i] = true;
                    }
                }
            }
        }
    }
    let dead: Vec<usize> = alive.iter().enumerate().filter(|(_, a)| !**a).map(|(i, _)| i).collect();
    assert!(dead.is_empty(), "⛔ DEAD residual(s) {dead:?} of {}: no single-cell nudge on any honest row moves them", alive.len());
}

/// The block's clock law, standalone: one row holding a row clock and the compare, the block's clock a constant.
#[derive(Clone)]
struct ClockLeGate {
    block: Ea4,
}
impl crate::air_zerocheck::AirConstraint for ClockLeGate {
    fn degree(&self, _nvars: usize) -> usize {
        2
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut rs = Vec::new();
        push_clock_le(&mut rs, local, 1, local[0], self.block);
        let mut acc = Ea4::ZERO;
        for (i, r) in rs.into_iter().enumerate() {
            acc += Ea4::from(Fa4::from_u64(i as u64 + 1)) * r;
        }
        acc
    }
    fn is_row_local(&self) -> bool {
        true
    }
}

fn clock_le_verifies(row: Vec<Fa4>, block_h: u64) -> bool {
    let cols = carrier_cols(&row);
    let gate = ClockLeGate { block: clock_const(block_h) };
    let bind = to_f(&clock_lanes(block_h)).to_vec();
    let g2 = gate.clone();
    let Some(bytes) = prove_air_direct_light_decider_selfcontained_bytes(cols, move |_g: Ea4| gate.clone(), &bind) else {
        return false;
    };
    let shape = (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, 1 + CLOCK_LE_WIDTH);
    verify_air_direct_light_decider_selfcontained_bytes(&bytes, move |_g: Ea4| g2.clone(), &bind, shape)
}

fn clock_le_row(row_h: u64, block_h: u64) -> Option<Vec<Fa4>> {
    let mut row = vec![Fa4::ZERO; 1 + CLOCK_LE_WIDTH];
    row[0] = Fa4::from_u64(row_h);
    fill_clock_le(&mut row, 1, row_h, block_h)?;
    Option::from(row)
}

#[test]
fn a_ledger_row_whose_clock_is_past_the_blocks_has_no_witness() {
    let block = 500_001u64;
    assert!(clock_le_verifies(clock_le_row(block, block).expect("lays"), block), "a row at the block's clock verifies");
    assert!(clock_le_verifies(clock_le_row(0, block).expect("lays"), block), "a row at clock 0 verifies");
    assert!(clock_le_verifies(clock_le_row(block - 1, block).expect("lays"), block), "an hour behind verifies");
    // the honest filler has no row for a clock past the block's, or past an hour count's range
    assert!(clock_le_row(block + 1, block).is_none());
    assert!(clock_le_row(0, 1 << HOUR_BITS).is_none());
    // a hostile row: the honest block for (row = block), then the row's clock cell moved one hour ahead
    let mut row = clock_le_row(block, block).expect("lays");
    row[0] = Fa4::from_u64(block + 1);
    assert!(!clock_le_verifies(row, block), "⛔ a row clock past the block's verified");
    // a hostile row whose compare is laid for a LATER block clock than the verifier's
    let row = clock_le_row(block + 1, block + 1).expect("lays");
    assert!(!clock_le_verifies(row, block), "⛔ a row laid against another block clock verified");
    // wrap-around: a slack of −1 is p − 1 in the field, which no 22 boolean cells sum to; the nearest a prover can
    // lay is every slack bit set
    let mut row = clock_le_row(block, block).expect("lays");
    row[0] = Fa4::from_u64(block + 1);
    for k in 0..HOUR_BITS {
        row[1 + LE_A_BITS + k] = Fa4::from_u64(((block + 1) >> k) & 1);
        row[1 + LE_SLACK_BITS + k] = Fa4::ONE;
    }
    assert!(!clock_le_verifies(row, block), "⛔ a wrapped slack verified");
    // a row clock that is not an hour count: its cell holds p − 1 (the field's −1), so the block's clock would exceed it
    let mut row = clock_le_row(0, block).expect("lays");
    row[0] = -Fa4::ONE;
    assert!(!clock_le_verifies(row, block), "⛔ a row clock outside an hour count's range verified");
}

/// MEASURED, not declared: what the vault region costs EVERY payment, beside the same payment proven by the gate
/// without the region (same binary, same load). Printed for the spec; the bound asserted is the pillar's.
#[test]
fn the_note_class_spend_is_measured_with_the_vault_region() {
    let p = parties();
    let w = witness(p.a, 5_000_000 + FEE, lanes_of(&[1, 1, 1, 1]));
    let d = test_clue_digest(1);
    let runs = 5;
    let median = |mut v: Vec<u128>| {
        v.sort_unstable();
        v[v.len() / 2]
    };
    let (mut prove_ms, mut verify_ms, mut bytes) = (Vec::new(), Vec::new(), 0);
    for _ in 0..runs {
        let t0 = std::time::Instant::now();
        let (carrier, cms, nf, lc, tag1) = prove_note_spend_bytes(&w, &NoteSpendExtras::plain(T), d, w.lc_blind, 0).expect("proves");
        prove_ms.push(t0.elapsed().as_millis());
        let t1 = std::time::Instant::now();
        assert!(verify_note_spend_bytes(&carrier, cms[0], cms[1], nf, lc, d, tag1, FEE, T));
        verify_ms.push(t1.elapsed().as_millis());
        bytes = carrier.len();
    }
    // the SAME payment through the gate with no vault region: the row and the carrier every spend had before
    let (row, cms, nf, lc) = spend_validity_row(&w).expect("the plain row lays");
    let tag1_f: DigestF = core::array::from_fn(|c| row[SV_CLAIM_BLK + crate::pow_pq_air::PERM_OUT + c]);
    let bind = validity_public_bind_with_commit(&cms, &nf, &lc, &to_f(&d), &tag1_f);
    let (mut old_ms, mut old_bytes) = (Vec::new(), 0);
    for _ in 0..runs {
        let row = row.clone();
        let cols = carrier_cols(&row);
        let make = move |g: Ea4| SpendValidityGate { vault: None, ..gate_of(&row, &cms, &nf, &lc, 0, g) };
        let t0 = std::time::Instant::now();
        let carrier = crate::committed_air::prove_air_blinded_bytes(cols, make, &bind).expect("the region-free carrier proves");
        old_ms.push(t0.elapsed().as_millis());
        old_bytes = carrier.len();
    }
    eprintln!(
        "[vault-cost] note-class spend: row {} columns = plain {} + vault region {}; carrier {bytes} B (without the region {old_bytes} B, +{} B); prove median {} ms (without the region {} ms); verify median {} ms",
        note_spend_row_width(),
        spend_validity_row_width(),
        VAULT_BLK_WIDTH,
        bytes as i64 - old_bytes as i64,
        median(prove_ms),
        median(old_ms),
        median(verify_ms)
    );
    assert!(bytes <= 1_800_000, "the constant-proof pillar");
}
