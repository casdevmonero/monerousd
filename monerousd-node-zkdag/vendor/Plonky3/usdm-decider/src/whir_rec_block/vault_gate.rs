// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE VAULT — a note with three ways out instead of one (docs/GOODS-AND-SERVICES-LAYER-SPEC-20261109.md §9.1).
//!
//! A protected purchase locks the price in a vault note. It leaves in exactly three ways, each a branch of the ONE
//! note-class spend row, so a vault spend and a payment are the same proof shape and the verifier never learns which
//! branch held:
//!
//! ```text
//! lock 1    the taker lock 1 names (the seller), holding its secret (the buyer's handover code)
//! lock 2    the taker lock 2 names (the buyer), holding its secret (the seller's refund code)
//! clock     the note's owner (the default party), once the chain clock is at or past T
//! ```
//!
//! THE NOTE. A vault note IS an ordinary note of its default party — `o = P(spk_owner, seed)`, the same owner block,
//! the same two opening compressions — with three things written in lanes that are zero on every ordinary note:
//!
//! ```text
//! tag   = [asset, KIND, lock 1 (4 lanes)]        KIND = 2^22 + T, T in chain hours; 0 on an ordinary note
//! value = [limb 0..3, lock 2 (4 lanes)]
//! lock  = the first 4 lanes of the claim tag  P([CLAIM, 0, 1, 0, taker spk 0..3], [secret 0..3, o 0..3])
//! nf    = P(o, cm)                               both parties hold o, so the vault has ONE nullifier whoever spends
//! ```
//!
//! ⭐ NO NEW COMPRESSION (lane dcash's acceptance condition, 2026-11-09: a block's cycle is ~95 % the joined prove, so
//! a payment that uses no vault must cost almost nothing more). Every block a vault spend needs is one a payment
//! already lays: the owner block proves the spender's own `spk`; the claim block, which every spend lays to publish its
//! claim tag, computes the lock's preimage on a lock branch, so the spend's published claim tag IS the opened lock; the
//! nullifier block is keyed by `o` instead of `nk`. The region is three branch bits and one 44-bit compare.
//!
//! ⛔ WHY THE KIND LANE (refuted on paper before the diff, 2026-11-09). The plain branch opens any note whose owner the
//! spender is, and a vault's default party IS its owner. The plain branch welds the kind and lock lanes to 0, so it
//! cannot open a vault note; the clock branch welds the kind to `2^22 + T` with `T ≤ clock`; a lock branch welds a
//! lock's lanes to the claim tag it lays.
//!
//! ⛔ ONE NULLIFIER, WHOEVER SPENDS. With each party's own `nk` two branches would lay two nullifiers and both spends
//! would land: the double pay this construction exists to make impossible. The set refuses the second (the Zcash
//! nullifier shape, borrowed).
//!
//! ⛔ A LOCK NAMES ITS TAKER AND ITS VAULT. The claim tag a lock branch lays is published and enters the spent set like
//! every claim tag. Its preimage holds the taker's `spk` lanes, so nobody else can lay it (the other party, who knows
//! the secret, cannot publish the tag first and block the taker), and the vault's opening lanes, so one secret used in
//! two vaults lays two tags. The seller refreshes the seed of every vault it accepts, so no buyer can aim a new vault
//! at a tag already spent.
//!
//! ⭐ THE DELIVERY LOCK (spec §3.3: a download, a license, a code, a ticket). The seller sells a KEY `k`. The lock is
//! then set by the SELLER over its own key, once for the whole listing, and it fills BOTH lock slots of the vault:
//!
//! ```text
//! h              = P([CLAIM, 1, 1, 0, seller spk 0..3], [k 0..3, listing salt 0..3])
//! lock 1, lock 2 = h[0..4], h[4..8]                                   (all eight lanes; the offer states h)
//! the claim publishes   tag[c]     = k[c] + o[c]        for c in 0..4  (o: the vault's opening)
//!                       tag[4 + c] = inner[4 + c]       for c in 0..4  (inner: the vault note's inner opening hash)
//! ```
//!
//! THE BUYER CHECKS THE LOCK WITH NO PROOF. `h` is the same for every buyer of a listing, so the offer states it and
//! the buyer's wallet, which builds the vault itself, locks the price under exactly that value. The one proof a
//! listing needs (that the key behind `h` opens the sealed content to what the offer names, [`super::content_gate`])
//! is made once by the seller and checked once by each buyer. A sale itself proves nothing extra.
//!
//! WHY EIGHT LANES. An ordinary lock is set by the party that does NOT take it, so only a preimage opens it and four
//! lanes (124 bits) are enough. A delivery lock is set by the party that takes it, and that party gains from two keys
//! under one lock (the buyer is shown one, the claim publishes the other). Four lanes would leave that at a 2^62
//! collision search; eight lanes make it 2^124. A delivery vault therefore has no refund-code branch: an undelivered
//! download comes back to the buyer by the clock.
//!
//! WHAT THE PUBLISHED TAG SHOWS, AND TO WHOM. The buyer holds the vault's opening and its inner hash: it recognises
//! the tag by its upper lanes and subtracts the opening from the lower ones to get `k`. Everyone else sees eight
//! uniform lanes. That includes an EARLIER BUYER of the same listing, who knows `k`, `h` and the salt: from another
//! sale's tag it can compute that vault's four opening lanes `o[0..4]` and nothing it can test them against, because
//! the vault's spent tag, its note and its inner hash each need the other four opening lanes as well. (This is why
//! the tag's upper lanes are the inner hash's and not `h`'s: `h` is public, and a tag carrying it could be matched to
//! its listing by anyone.) The seller cannot be paid without laying that tag: the gate welds it. The buyer finds the
//! spend by the vault's one spent tag. BORROWED: Maxwell's zero-knowledge contingent payment (2011), where a claim
//! reveals the hash lock's preimage; here the reveal is masked, so the chain still shows an ordinary spend. No column
//! and no compression is added to the spend row.
//!
//! THE SUBSCRIPTION VAULT is this same vault: one per period, owned by the merchant from `T` (paid while the
//! subscriber is offline), with lock 2 the SUBSCRIBER'S OWN (cancel any period alone, before the merchant takes it).
//!
//! cons: the note-class spend row grows by `VAULT_BLK_WIDTH` columns on 2,510 (three bits and a 44-bit compare) for
//! EVERY spend, used or not: the price of a vault spend being indistinguishable from a payment. Bytes and
//! milliseconds are measured by `vault_tests::the_note_class_spend_is_measured_with_the_vault_region`.

use super::*;

/// The lane of a note's tag that names its KIND: 0 for every ordinary note, `2^HOUR_BITS + T` for a vault.
pub const NOTE_KIND_LANE: usize = 3; // PRODUCTION-SCALE-REVIEWED: the INDEX of the kind lane among a tag's eight lanes, not a cover count
/// The lanes a lock occupies: the upper half of the tag (lock 1) and of the value block (lock 2).
pub const LOCK_LANES: usize = DIGEST_LANES - SC_LIMBS;
/// One chain hour, in ms: the grid every spend clock and every vault time sits on.
pub const CHAIN_HOUR_MS: u64 = 3_600_000;
/// Bits of an hour count: 2^22 hours is about 478 years.
pub const HOUR_BITS: usize = 22;
/// The kind lane of a vault whose time is hour 0; also the first hour count out of range.
const VAULT_KIND_BASE: u64 = 1 << HOUR_BITS;
/// The lane of the claim block's left input that is 1 on a lock's claim and 0 on every other claim.
const CLAIM_LOCK_LANE: usize = 2;
/// A spend has two output notes.
const SPEND_OUTPUTS: usize = 2;

/// `ms` in whole chain hours, or `None` past the range an hour count holds.
#[must_use]
pub fn chain_hours(ms: u64) -> Option<u64> {
    let h = ms / CHAIN_HOUR_MS;
    (h < VAULT_KIND_BASE).then_some(h)
}

// ---- `a ≤ b` for two hour counts: a and b − a are each `HOUR_BITS` bits
const LE_A_BITS: usize = 0;
const LE_SLACK_BITS: usize = LE_A_BITS + HOUR_BITS;
/// Width of one `a ≤ b` block.
pub(crate) const LE_HOURS_WIDTH: usize = LE_SLACK_BITS + HOUR_BITS;

/// `a ≤ b` IN-CIRCUIT, for hour counts: `a` and `b − a` are each the sum of `HOUR_BITS` boolean cells of this block.
/// Both are then below 2^22, their sum is below 2^23 (no wrap in a 31-bit field), so `b = a + (b − a)` holds over the
/// integers and `a ≤ b`. `b` is the verifier's own value. Returns `a` as the block states it, for the caller to weld
/// to whatever must not exceed `b`.
// Generic over the row's field (lane agg 2026-11-15, `gate_trace`): the parameter is NAMED `Ea4`, so the body is unchanged.
pub(crate) fn push_le_hours<Ea4: crate::gate_trace::GateAlg>(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_, Ea4>, base: usize, b: Ea4) -> Ea4 {
    let one = Ea4::ONE;
    let (mut rec_a, mut rec_s, mut pw) = (Ea4::ZERO, Ea4::ZERO, Ea4::ONE);
    for j in 0..HOUR_BITS {
        let (ab, sb) = (local[base + LE_A_BITS + j], local[base + LE_SLACK_BITS + j]);
        cs.push(ab * (ab - one));
        cs.push(sb * (sb - one));
        rec_a += ab * pw;
        rec_s += sb * pw;
        pw = pw + pw;
    }
    cs.push(rec_s - (b - rec_a));
    rec_a
}

/// The trace side of [`push_le_hours`]. `None` when `a > b` or `b` is past an hour count's range: no block states it.
pub(crate) fn fill_le_hours(row: &mut [Fa4], base: usize, a: u64, b: u64) -> Option<()> {
    let slack = b.checked_sub(a)?;
    if b >= VAULT_KIND_BASE {
        return None;
    }
    for k in 0..HOUR_BITS {
        row[base + LE_A_BITS + k] = Fa4::from_u64((a >> k) & 1);
        row[base + LE_SLACK_BITS + k] = Fa4::from_u64((slack >> k) & 1);
    }
    Some(())
}

// ---- layout of the vault region, relative to its base (the end of the plain row)
/// Three one-hot branch bits: lock 1, lock 2, clock. Their sum says the spent note is a vault.
pub(super) const VB_SEL: usize = 0;
/// `T ≤ clock` on the clock branch (off it, `0 ≤ clock`).
pub(super) const VB_CLOCK: usize = VB_SEL + VaultBranch::ALL.len();
/// Width of the vault region.
pub const VAULT_BLK_WIDTH: usize = VB_CLOCK + LE_HOURS_WIDTH;

/// A lock: four lanes a vault note carries, opened by one taker with one secret.
pub type VaultLock = [u64; LOCK_LANES];
/// A lock's secret: four lanes (124 bits) the party that sets the lock draws.
pub type VaultSecret = [u64; LOCK_LANES];
/// The lock no taker opens (its lanes are zero, and no claim tag begins with four zero lanes).
pub const NO_LOCK: VaultLock = [0; LOCK_LANES];

/// The lock `taker_spk` opens with `secret`, on the vault whose opening is `opening`: the first four lanes of the
/// claim tag the taker's spend lays.
#[must_use]
pub fn vault_lock(taker_spk: &Digest, secret: &VaultSecret, opening: &Digest) -> VaultLock {
    let tag = poseidon_pair(lock_claim_left(taker_spk, false), lock_claim_key(secret, opening));
    core::array::from_fn(|c| tag[c])
}

/// A listing's salt: four lanes the seller draws once, stated in its offer.
pub type ListingSalt = [u64; LOCK_LANES];

/// THE DELIVERY LOCK `taker_spk` (a seller) sets over its own key `secret` for a listing with `salt`: the claim hash
/// under slot lane 1, all eight lanes, as a vault's `[lock 1, lock 2]`. The same for every buyer of the listing.
/// Whoever opens it publishes the key to the vault's other party.
#[must_use]
pub fn delivery_locks(taker_spk: &Digest, secret: &VaultSecret, salt: &ListingSalt) -> [VaultLock; 2] {
    let h = delivery_claim_hash(taker_spk, secret, salt);
    [core::array::from_fn(|c| h[c]), core::array::from_fn(|c| h[LOCK_LANES + c])]
}

/// The claim hash a delivery lock is: `P([CLAIM, 1, 1, 0, taker spk 0..3], [secret, salt])`.
#[must_use]
pub fn delivery_claim_hash(taker_spk: &Digest, secret: &VaultSecret, salt: &ListingSalt) -> Digest {
    let (left, key) = delivery_claim_inputs(taker_spk, secret, salt);
    poseidon_pair(left, key)
}

/// The two inputs of [`delivery_claim_hash`]: what a proof about a delivery lock lays in its own block.
#[must_use]
pub fn delivery_claim_inputs(taker_spk: &Digest, secret: &VaultSecret, salt: &ListingSalt) -> (Digest, Digest) {
    let mut key = [0u64; DIGEST_LANES];
    key[..LOCK_LANES].copy_from_slice(secret);
    key[LOCK_LANES..].copy_from_slice(salt);
    (lock_claim_left(taker_spk, true), key)
}

/// The claim tag a DELIVERY claim of `vault` publishes: the key plus the vault's opening in the lower lanes, the
/// vault note's inner hash in the upper ones. What the seller's wallet states as its spend's claim tag.
#[must_use]
pub fn delivery_claim_tag(vault: &VaultNote, secret: &VaultSecret) -> Digest {
    use p3_field::PrimeField64;
    let (opening, inner) = (vault.opening(), vault.inner());
    core::array::from_fn(|c| if c < LOCK_LANES { (Fa4::from_u64(secret[c]) + Fa4::from_u64(opening[c])).as_canonical_u64() } else { inner[c] })
}

/// BUYER: the key a tag laid beside `vault`'s spent tag carries. `None` when the tag is not this vault's delivery
/// claim (its upper lanes are not the vault's inner hash). The caller checks the key against the lock it funded
/// ([`delivery_locks`]) before using it.
#[must_use]
pub fn delivered_secret(claim_tag: &Digest, vault: &VaultNote) -> Option<VaultSecret> {
    use p3_field::PrimeField64;
    let (opening, inner) = (vault.opening(), vault.inner());
    if claim_tag[LOCK_LANES..] != inner[LOCK_LANES..] {
        return None;
    }
    Some(core::array::from_fn(|c| (Fa4::from_u64(claim_tag[c]) - Fa4::from_u64(opening[c])).as_canonical_u64()))
}

/// The claim a lock's taker lays to open it, as the two inputs of the claim compression and the tag they hash to
/// (the taker's spend publishes that tag; its first four lanes are the lock). A wallet needs these for the taker's
/// constant-width tag-set proof, which states the claim tag as a real row.
#[must_use]
pub fn vault_lock_claim(taker_spk: &Digest, secret: &VaultSecret, opening: &Digest) -> (Digest, Digest, Digest) {
    let (left, key) = (lock_claim_left(taker_spk, false), lock_claim_key(secret, opening));
    (left, key, poseidon_pair(left, key))
}

/// The lane of the claim's left input that holds a device-slot claim's slot number. On a lock's claim it is 0, or 1
/// when the lock is a delivery lock.
const CLAIM_SLOT_LANE: usize = 1; // PRODUCTION-SCALE-REVIEWED: the INDEX of a lane among the claim's eight, not a count

fn lock_claim_left(taker_spk: &Digest, deliver: bool) -> Digest {
    let mut left = [0u64; DIGEST_LANES];
    left[0] = crate::slot_ledger::SLOT_CLAIM_DOMAIN;
    left[CLAIM_SLOT_LANE] = u64::from(deliver);
    left[CLAIM_LOCK_LANE] = 1;
    left[SC_LIMBS..].copy_from_slice(&taker_spk[..LOCK_LANES]);
    left
}

fn lock_claim_key(secret: &VaultSecret, opening: &Digest) -> Digest {
    let mut key = [0u64; DIGEST_LANES];
    key[..LOCK_LANES].copy_from_slice(secret);
    key[LOCK_LANES..].copy_from_slice(&opening[..DIGEST_LANES - LOCK_LANES]);
    key
}

/// The lanes a note carries beside its asset and its value: zero on every ordinary note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NoteExt {
    /// Tag lane [`NOTE_KIND_LANE`].
    pub(super) kind: u64,
    /// Tag lanes 4..8.
    pub(super) lock1: VaultLock,
    /// Value-block lanes 4..8.
    pub(super) lock2: VaultLock,
}

impl NoteExt {
    /// An ordinary note: every extra lane zero.
    pub(super) const PLAIN: NoteExt = NoteExt { kind: 0, lock1: NO_LOCK, lock2: NO_LOCK };

    /// The tag's lanes from [`NOTE_KIND_LANE`] on: the kind, then lock 1.
    pub(super) fn tag_hi(&self) -> [u64; DIGEST_LANES - NOTE_KIND_LANE] {
        core::array::from_fn(|i| if i == 0 { self.kind } else { self.lock1[i - 1] })
    }
}

/// A vault: everything its two parties agree on before money moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultNote {
    /// The default party's address key: it owns the note and takes it alone from `t_h` on.
    pub owner_spk: Digest,
    /// The note's seed. Both parties hold it; the party that ACCEPTS a vault draws part of it, so every vault it
    /// accepts has a fresh opening.
    pub seed: Digest,
    /// From this chain hour on (`chain_hours` of the chain clock) the owner may take the note.
    pub t_h: u64,
    /// Opened by lock 1's taker with its secret, at any time. [`NO_LOCK`] for none.
    pub lock1: VaultLock,
    /// Opened by lock 2's taker with its secret, at any time. [`NO_LOCK`] for none.
    pub lock2: VaultLock,
}

impl VaultNote {
    /// The vault's time is an hour count. A vault that is not well formed has no clock branch; no wallet makes or
    /// accepts one.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.t_h < VAULT_KIND_BASE
    }

    /// The vault note's opening, which a sender writes to create the vault. It is also the vault's key in the spent
    /// set: both parties hold it, nobody else does.
    #[must_use]
    pub fn opening(&self) -> Digest {
        owner_opening(&self.owner_spk, &self.seed)
    }

    pub(super) fn ext(&self) -> NoteExt {
        NoteExt { kind: VAULT_KIND_BASE + self.t_h, lock1: self.lock1, lock2: self.lock2 }
    }

    /// The vault note's inner opening hash, `P([0, 0, 0, kind, lock 1], opening)`: what its commitment wraps with the
    /// amount. Both parties compute it; it is never published whole.
    #[must_use]
    pub fn inner(&self) -> Digest {
        ext_note_inner(&self.ext(), self.opening())
    }

    /// The vault note's commitment: what the spend that creates the vault publishes as an output, and what either
    /// party looks for on the chain.
    #[must_use]
    pub fn note_cm(&self, amount: u64) -> Digest {
        ext_note_cm(amount, &self.ext(), self.opening())
    }

    /// The one tag a spend of this vault lays in the spent set, whichever branch it takes.
    #[must_use]
    pub fn spent_tag(&self, amount: u64) -> Digest {
        note_nullifier(&self.opening(), &self.note_cm(amount))
    }
}

/// A USDm note's commitment with its extra lanes: `P([limbs, lock 2], P([0, 0, 0, kind, lock 1], o))`. With
/// [`NoteExt::PLAIN`] this is `asset_note_cm(amount, USDM_ASSET_TAG, o)`.
pub(super) fn ext_note_cm(amount: u64, ext: &NoteExt, opening: Digest) -> Digest {
    let mut value = [0u64; DIGEST_LANES];
    value[..SC_LIMBS].copy_from_slice(&note_value_lanes(amount));
    value[SC_LIMBS..].copy_from_slice(&ext.lock2);
    poseidon_pair(value, ext_note_inner(ext, opening))
}

/// The inner compression of [`ext_note_cm`]: `P([0, 0, 0, kind, lock 1], o)`.
pub(super) fn ext_note_inner(ext: &NoteExt, opening: Digest) -> Digest {
    let mut tag = [0u64; DIGEST_LANES];
    tag[NOTE_KIND_LANE..].copy_from_slice(&ext.tag_hi());
    poseidon_pair(tag, opening)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultBranch {
    Lock1,
    Lock2,
    Clock,
}

impl VaultBranch {
    /// Every branch, in the order the region lays its selector bits.
    pub const ALL: [VaultBranch; 3] = [VaultBranch::Lock1, VaultBranch::Lock2, VaultBranch::Clock];
}

/// The witness of a vault spend, beside the spend row's own. The spender's keys are the spend witness's
/// `owner.ask` and `owner.nk`; its `owner.seed` is the vault's seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultOpen {
    pub note: VaultNote,
    pub branch: VaultBranch,
    /// The lock's secret on a lock branch. Not read on the clock branch.
    pub secret: VaultSecret,
    /// `Some(salt)` when the lock opened is a DELIVERY lock of the listing with that salt: the claim publishes
    /// `secret` to the vault's other party.
    pub deliver: Option<ListingSalt>,
}

/// What a note-class spend adds to its row beside the plain spend's witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteSpendExtras {
    /// Output j is this vault (the witness's `outN_opening` is its [`VaultNote::opening`]).
    pub out_vaults: [Option<VaultNote>; SPEND_OUTPUTS],
    /// `Some` when the spent note is a vault.
    pub vault: Option<VaultOpen>,
    /// The chain clock this spend is proven against, in chain hours. The verifier supplies the same value.
    pub clock_h: u64,
}

impl NoteSpendExtras {
    /// An ordinary payment.
    #[must_use]
    pub fn plain(clock_h: u64) -> Self {
        NoteSpendExtras { out_vaults: [None; SPEND_OUTPUTS], vault: None, clock_h }
    }

    /// A payment whose first output opens the vault `note` (the buyer's side of a protected purchase).
    #[must_use]
    pub fn opening_vault(note: &VaultNote, clock_h: u64) -> Self {
        let mut x = Self::plain(clock_h);
        x.out_vaults[0] = Option::from(*note);
        x
    }

    /// A spend of the vault `note` through `branch` (`secret` is the lock's on a lock branch, unread on clock).
    #[must_use]
    pub fn spending_vault(note: VaultNote, branch: VaultBranch, secret: VaultSecret, clock_h: u64) -> Self {
        let mut x = Self::plain(clock_h);
        x.vault = Option::from(VaultOpen { note, branch, secret, deliver: None });
        x
    }

    /// A spend of the vault `note` through its DELIVERY lock 1 with the seller's own key `secret`: the claim this
    /// spend publishes hands `secret` to the vault's other party.
    #[must_use]
    pub fn delivering(note: VaultNote, secret: VaultSecret, salt: ListingSalt, clock_h: u64) -> Self {
        let mut x = Self::plain(clock_h);
        x.vault = Option::from(VaultOpen { note, branch: VaultBranch::Lock1, secret, deliver: Option::from(salt) });
        x
    }

    /// The honest-prover bound (the gate is the dishonest-prover one): a vault branch is laid only by the party it
    /// names, with the secret it names, at or after the vault's time on the clock branch; and an output named a vault
    /// carries that vault's opening.
    pub(super) fn fits(&self, w: &SpendValidityWitness) -> bool {
        let outs = [w.out0_opening, w.out1_opening];
        let outs_ok =
            (0..SPEND_OUTPUTS).all(|j| self.out_vaults[j].as_ref().is_none_or(|v| v.is_well_formed() && v.opening() == outs[j]));
        let spk_p = owner_spk(&w.owner.ask, &w.owner.nk);
        let in_ok = self.vault.as_ref().is_none_or(|v| {
            let lock_of = |l: &VaultLock| *l != NO_LOCK && v.deliver.is_none() && vault_lock(&spk_p, &v.secret, &v.note.opening()) == *l;
            // a delivery claim opens the eight-lane lock, through lock 1 only
            let delivers = || v.deliver.as_ref().is_some_and(|salt| delivery_locks(&spk_p, &v.secret, salt) == [v.note.lock1, v.note.lock2]);
            w.owner.seed == v.note.seed
                && match v.branch {
                    VaultBranch::Lock1 => lock_of(&v.note.lock1) || delivers(),
                    VaultBranch::Lock2 => lock_of(&v.note.lock2),
                    VaultBranch::Clock => spk_p == v.note.owner_spk && v.note.t_h <= self.clock_h,
                }
        });
        outs_ok && in_ok
    }

    pub(super) fn in_ext(&self) -> NoteExt {
        self.vault.as_ref().map_or(NoteExt::PLAIN, |v| v.note.ext())
    }

    pub(super) fn out_ext(&self) -> [NoteExt; SPEND_OUTPUTS] {
        core::array::from_fn(|j| self.out_vaults[j].as_ref().map_or(NoteExt::PLAIN, VaultNote::ext))
    }

    /// How a lock branch lays the blocks it shares with a payment; `None` on a payment and on the clock branch.
    pub(super) fn lock_lay(&self) -> Option<LockLay> {
        let v = self.vault.as_ref().filter(|v| v.branch != VaultBranch::Clock)?;
        Option::from(LockLay { owner_spk: v.note.owner_spk, secret: v.secret, deliver: v.deliver })
    }
}

/// The verifier's clock, in chain hours, as the gate's constant.
#[must_use]
pub fn clock_const(clock_h: u64) -> Ea4 {
    Ea4::from(Fa4::from_u64(clock_h))
}

/// The lanes the public bind carries in its seventh slot: the clock's hour count in lane 0, then zeros.
#[must_use]
pub fn clock_lanes(clock_h: u64) -> Digest {
    crate::poseidon2_compress::lanes_of(&[clock_h])
}

/// The clock a carrier's clock lanes state: an hour count in lane 0, the other lanes zero. `None` for anything else
/// (no honest prover lays it; a ledger refuses to state it).
#[must_use]
pub fn clock_of_lanes(d: &Digest) -> Option<u64> {
    (d[0] < VAULT_KIND_BASE && d[1..].iter().all(|l| *l == 0)).then_some(d[0])
}

/// Width of one `row clock ≤ block clock` block of the block ledger.
pub(crate) const CLOCK_LE_WIDTH: usize = LE_HOURS_WIDTH;

/// ⭐ THE BLOCK'S CLOCK LAW, one ledger row (spec §9.1; BORROWED: Bitcoin's BIP113, a lock judged by the chain's
/// median-time-past): the clock this row's carrier was proven against — `row_clock`, lane 0 of the seventh slot its
/// transcript absorbed — is AT OR BEFORE the block's clock, and is an hour count ([`push_le_hours`]).
///
/// Why here and not on the wire: a spend's clock names the hour its proof was made. Published per row it would tell
/// real rows from cover rows and date every spend, so it stays in the row's ABSORBED tuple (never published) and the
/// block states ONE clock for all its rows. Without this law a producer could include a vault's clock-branch spend
/// proven against a clock the chain has not reached.
pub(crate) fn push_clock_le<Ea4: crate::gate_trace::GateAlg>(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_, Ea4>, base: usize, row_clock: Ea4, block_clock: Ea4) {
    let a = push_le_hours(cs, local, base, block_clock);
    cs.push(a - row_clock);
}

/// The trace side of [`push_clock_le`]. `None` when the row's clock is past the block's: no block can state that row.
pub(crate) fn fill_clock_le(row: &mut [Fa4], base: usize, row_clock_h: u64, block_clock_h: u64) -> Option<()> {
    fill_le_hours(row, base, row_clock_h, block_clock_h)
}

/// What the vault region hands the rest of the gate.
pub(super) struct VaultWires<Ea4 = crate::hiding_decider::Ea4> {
    /// 1 when the spent note is a vault.
    pub(super) v: Ea4,
    /// 1 on the lock 1 branch, on the lock 2 branch.
    pub(super) lk1: Ea4,
    pub(super) lk2: Ea4,
}

impl<Ea4: crate::gate_trace::GateAlg> VaultWires<Ea4> {
    /// 1 on either lock branch.
    pub(super) fn lk(&self) -> Ea4 {
        self.lk1 + self.lk2
    }
}

/// THE VAULT REGION IN-CIRCUIT, at `base`. `kind` is the spent note's kind lane (a cell of its opening's inner
/// compression). The welds that multiplex the spend's own blocks are the caller's, from the returned wires.
pub(super) fn push_vault<Ea4: crate::gate_trace::GateAlg>(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_, Ea4>, base: usize, kind: Ea4, clock: Ea4) -> VaultWires<Ea4> {
    let one = Ea4::ONE;
    // the branch bits: each a bit, at most one set
    let (lk1, lk2, clk) = (local[base + VB_SEL], local[base + VB_SEL + 1], local[base + VB_SEL + 2]);
    for b in [lk1, lk2, clk] {
        cs.push(b * (b - one));
    }
    let v = lk1 + lk2 + clk;
    cs.push(v * (v - one));
    // the compare states some hour count `a ≤ clock` on every row (which also holds the clock to an hour count); on
    // the clock branch the vault's time IS that count
    let a = push_le_hours(cs, local, base + VB_CLOCK, clock);
    cs.push(clk * (kind - Ea4::from(Fa4::from_u64(VAULT_KIND_BASE)) - a));
    VaultWires { v, lk1, lk2 }
}

/// What a lock branch's claim block reads in lane `c` of its left input, where an ordinary claim reads zero: the
/// lock marker and the taker's `spk` lanes. Lanes 0 and 1 (the claim domain and `d`) are every claim's.
pub(super) fn claim_left_lock_lane<Ea4: crate::gate_trace::GateAlg>(w: &VaultWires<Ea4>, c: usize, spk: &dyn Fn(usize) -> Ea4) -> Ea4 {
    if c == CLAIM_LOCK_LANE {
        w.lk()
    } else if c >= SC_LIMBS {
        w.lk() * spk(c - SC_LIMBS)
    } else {
        Ea4::ZERO
    }
}

/// The trace side of [`push_vault`]: lays the region exactly as `x` says, true or not (the gate judges it). `None`
/// only when the clock branch is asked for before its time, which no compare block can lay.
pub(super) fn fill_vault(row: &mut [Fa4], base: usize, x: &NoteSpendExtras) -> Option<()> {
    let bit = |b: bool| Fa4::from_u64(u64::from(b));
    let branch = x.vault.as_ref().map(|v| v.branch);
    for (i, b) in VaultBranch::ALL.iter().enumerate() {
        row[base + VB_SEL + i] = bit(branch == Option::from(*b));
    }
    let t = match &x.vault {
        Some(v) if v.branch == VaultBranch::Clock => v.note.t_h,
        _ => 0,
    };
    fill_le_hours(row, base + VB_CLOCK, t, x.clock_h)
}

/// How a lock branch lays the blocks it shares with a payment.
pub(super) struct LockLay {
    /// The vault's owner key: the opening's left input (the spender is not the owner).
    pub(super) owner_spk: Digest,
    pub(super) secret: VaultSecret,
    /// A delivery lock's claim (the listing's salt): the slot lane is 1 and the published tag carries the secret.
    pub(super) deliver: Option<ListingSalt>,
}

impl LockLay {
    /// The claim block's two inputs on a lock branch, for a spender whose address key is `spk_p`.
    pub(super) fn claim_inputs(&self, spk_p: &Digest, opening: &Digest) -> (Digest, Digest) {
        match &self.deliver {
            Some(salt) => delivery_claim_inputs(spk_p, &self.secret, salt),
            None => (lock_claim_left(spk_p, false), lock_claim_key(&self.secret, opening)),
        }
    }
}

/// THE CLAIM TAG A NOTE-CLASS SPEND PUBLISHES, read from its row (one spelling for the prover and its pins): the claim
/// block's output, except on the lock 1 branch with the slot cell 1 (a delivery claim), where the first
/// [`LOCK_LANES`] lanes are the key cells plus the spent note's opening lanes and the rest are the spent note's inner
/// hash. The same expression the gate welds the public tag to. `in_inner` is the base of the spent note's inner
/// opening block.
pub(super) fn published_claim_tag(row: &[Fa4], vault_base: usize, in_inner: usize) -> DigestF {
    let deliver = row[vault_base + VB_SEL] * row[SV_CLAIM_D];
    core::array::from_fn(|c| {
        let out = row[SV_CLAIM_BLK + crate::pow_pq_air::PERM_OUT + c];
        let said = if c < LOCK_LANES { row[SV_CLAIM_KEY + c] + row[SV_SK + c] } else { row[in_inner + crate::pow_pq_air::PERM_OUT + c] };
        out + deliver * (said - out)
    })
}

/// The gate's side of [`published_claim_tag`], lane `c`: what the public claim tag is welded to.
pub(super) fn claim_tag_lane<Ea4: crate::gate_trace::GateAlg>(w: Option<&VaultWires<Ea4>>, local: &crate::air_zerocheck::Row<'_, Ea4>, in_inner: usize, c: usize) -> Ea4 {
    let out = local[SV_CLAIM_BLK + crate::pow_pq_air::PERM_OUT + c];
    let Some(w) = w else { return out };
    let said = if c < LOCK_LANES { local[SV_CLAIM_KEY + c] + local[SV_SK + c] } else { local[in_inner + crate::pow_pq_air::PERM_OUT + c] };
    out + w.lk1 * local[SV_CLAIM_D] * (said - out)
}

/// What a lock claim's key holds in its upper lanes, as a law per lane: the VAULT's opening lanes on an ordinary lock
/// claim (one secret in two vaults lays two tags), and nothing fixed on a delivery claim, whose upper lanes are the
/// listing's salt (bound by the lock itself, which is the claim's whole hash).
pub(super) fn push_claim_key_upper<Ea4: crate::gate_trace::GateAlg>(cs: &mut Vec<Ea4>, w: &VaultWires<Ea4>, local: &crate::air_zerocheck::Row<'_, Ea4>) {
    let ordinary = w.lk() - w.lk1 * local[SV_CLAIM_D];
    for c in 0..LOCK_LANES {
        cs.push(ordinary * (local[SV_CLAIM_KEY + LOCK_LANES + c] - local[SV_SK + c]));
    }
}

/// THE DELIVERY CLAIM'S OWN LAWS (the caller pushes the lock-1 and lock-2 welds every lock branch has). On the lock 1
/// branch the slot cell is a bit, and when it is 1 the claim's upper lanes are the spent note's lock-2 lanes, so the
/// lock opened is the whole eight-lane hash. On the lock 2 branch the slot cell is 0: one way to open each lock.
/// `lock2(c)` is lane `c` of the spent note's lock 2.
pub(super) fn push_delivery<Ea4: crate::gate_trace::GateAlg>(cs: &mut Vec<Ea4>, w: &VaultWires<Ea4>, local: &crate::air_zerocheck::Row<'_, Ea4>, lock2: &dyn Fn(usize) -> Ea4) {
    let d = local[SV_CLAIM_D];
    cs.push(w.lk1 * d * (d - Ea4::ONE));
    cs.push(w.lk2 * d);
    for c in 0..LOCK_LANES {
        cs.push(w.lk1 * d * (local[SV_CLAIM_BLK + crate::pow_pq_air::PERM_OUT + LOCK_LANES + c] - lock2(c)));
    }
}

/// The note the spend `(w, x)` opens, read from the row the constraints check (one spelling). For a vault spend this
/// is the vault note itself, the value the spend that CREATED the vault published as an output.
#[must_use]
pub fn note_spend_input_leaf(w: &SpendValidityWitness, x: &NoteSpendExtras) -> Option<Digest> {
    use p3_field::PrimeField64;
    let (row, ..) = note_spend_row(w, x, w.lc_blind, 0)?;
    let leaf: Digest = core::array::from_fn(|c| row[SV_LEAF + c].as_canonical_u64());
    Option::from(leaf)
}

#[cfg(test)]
mod vault_tests;
