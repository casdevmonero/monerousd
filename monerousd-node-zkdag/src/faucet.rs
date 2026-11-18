// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! **Testnet faucet** — a developer tool that ISSUES valueless *test* USDm on demand and seals it into an ordinary
//! confidential note addressed to a requester's wallet, so a developer (or a brand-new wallet) can get test coins
//! to move on testnet without anyone having to hand it value first. TESTNET-ONLY by construction: the RPC layer
//! gates every call on `node_network_is_testnet`, so this path can NEVER run on mainnet, where supply stays
//! conservation-bound by the 150%-backed PSM mint. It records each issued note on the ordinary note path the
//! recipient wallet scans — a real, recipient-owned, spendable leaf, not an in-process tally.
//!
//! The crypto is the ordinary confidential note:
//!   • `seal_note(ek, amount)` builds the exact 1153-byte note the desktop wallet's `scan_note` recovers —
//!     `note_cm(32) ‖ ML-KEM-768 ct(1088) ‖ enc_amount(32) ‖ view_tag(1)`, with
//!     `note_cm = usdm_decider::asset_note_cm(amount, USDM_ASSET_TAG, sk)` (the two-round commitment) and every field
//!     derived from the fresh ML-KEM shared secret, so an observer learns nothing (Pillar-1).
//!   • `scan_note(note, dk)` decapsulates + checks the view-tag and Poseidon binding — the recipient recovers the
//!     amount LOCALLY with its own key; the node never holds a user's scan key.
//!
//! A held demo recipient keypair (tool-owned, NOT a user key) lets the node `scan_note` what it forwarded and
//! PROVE the value landed — so the harness can confirm funds moved without a browser wallet.

use crate::pqkem;
use crate::spend_frontier::leaf_to_cm_bytes;

/// The confidential-note layout (identical to the wallet's `pq.rs` and the node's served `crate::cover` note).
pub const PQ_NOTE_BYTES: usize = 1153;
const NOTE_CT_OFF: usize = 32;
const NOTE_CT_END: usize = NOTE_CT_OFF + 1088; // 1120
const NOTE_ENC_END: usize = NOTE_CT_END + 32; // 1152
const NOTE_VT_OFF: usize = NOTE_ENC_END; // 1152


fn note_kdf(ss: &[u8], tag: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ss);
    h.update(tag);
    *h.finalize().as_bytes()
}

/// ⛔⛔⛔ DB-395 — the note's per-note SEED from the ML-KEM shared secret. Sender and recipient derive the SAME seed (through
/// the crate's ONE map from 32 KDF bytes into a digest, `hash32_to_digest`), and it is NOT a key: the note commits to
/// `o = P(spk_recipient, seed)` and a spend proves the recipient's `(ask, nk)` behind `spk`. This was `note_sk_from_ss`, and
/// the value it returned WAS the spend key — so every sealer (a payer, the faucet, a node sealing a reward) could spend what
/// it sealed and compute its nullifier. The wallet's twin (`pq.rs::note_seed_from_ss`, same domain tag) derives the
/// recipient's copy and follows this definition.
pub fn note_seed_from_ss(ss: &[u8]) -> crate::spend_frontier::Digest4 {
    usdm_decider::poseidon2_compress::hash32_to_digest(&note_kdf(ss, b"MUSD-note-owner-seed-v1"))
}

/// The note's OPENING `o = P(spk, seed)` — what the sealer computes from the recipient's PUBLIC spend key and what the
/// commitment binds in the lane the spend key used to occupy (DB-395). It opens the commitment; it spends nothing.
pub fn note_opening(spk: &crate::spend_frontier::Digest4, ss: &[u8]) -> crate::spend_frontier::Digest4 {
    usdm_decider::whir_rec_block::owner_opening(spk, &note_seed_from_ss(ss))
}

/// `note_cm = asset_note_cm(amount, USDM_ASSET_TAG, o)` serialized to 32 bytes — a SPENDABLE Poseidon leaf,
/// byte-parity with the decider's spend opening and the wallet's `pq::note_cm`.
///
/// ⛔ ONE FORMULA, DEFINED ONCE IN THE DECIDER (2026-09-11): the two-round commitment
/// `P(limbs(amount), P([tag, 0], o))`. The old `poseidon_pair([amount, 0, 0, 0], sk)` bound the amount as
/// one field element mod p, so a note holding `v` could be spent as `v + p`. Never compute a commitment
/// here by hand again — a wallet/node disagreement on this one line is an unspendable note.
fn note_cm(spk: &crate::spend_frontier::Digest4, ss: &[u8], amount: u64) -> [u8; 32] {
    leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(
        amount,
        usdm_decider::whir_rec_block::USDM_ASSET_TAG,
        note_opening(spk, ss),
    ))
}

/// Seal `amount` into a 1153-byte confidential note addressed to `(ek, spk)` — the recipient's ML-KEM-768 encapsulation key
/// and its spend key (DB-395: the note commits to `o = P(spk, seed)`, so the sealer cannot spend it). `None` if `ek` is
/// malformed / the KEM fails (fail-closed — never a bad note).
pub fn seal_note(ek_bytes: &[u8], spk: &crate::spend_frontier::Digest4, amount: u64) -> Option<[u8; PQ_NOTE_BYTES]> {
    let (ss, ct) = pqkem::encapsulate(ek_bytes)?; // ss: 32, ct: 1088
    if ct.len() != 1088 {
        return None;
    }
    let amt = amount.to_le_bytes();
    let mut enc = note_kdf(&ss, b"MUSD-note-enc-v1");
    for i in 0..8 {
        enc[i] ^= amt[i]; // amount rides the first 8 bytes of the keystream
    }
    let vt = note_kdf(&ss, b"MUSD-note-vt-v1")[0];
    let cm = note_cm(spk, &ss, amount);
    let mut out = [0u8; PQ_NOTE_BYTES];
    out[0..NOTE_CT_OFF].copy_from_slice(&cm);
    out[NOTE_CT_OFF..NOTE_CT_END].copy_from_slice(&ct);
    out[NOTE_CT_END..NOTE_ENC_END].copy_from_slice(&enc);
    out[NOTE_VT_OFF] = vt;
    Some(out)
}

/// [`seal_note`] that also returns the note's opening `o = P(spk, seed)` — what a spend carrier binds for this output.
/// (§BR-5 B5-d: custody seals an escrow burn's change note back to the user's address at the batch.)
pub fn seal_note_with_opening(
    ek_bytes: &[u8],
    spk: &crate::spend_frontier::Digest4,
    amount: u64,
) -> Option<([u8; PQ_NOTE_BYTES], crate::spend_frontier::Digest4)> {
    let (ss, ct) = pqkem::encapsulate(ek_bytes)?;
    if ct.len() != 1088 {
        return None;
    }
    let amt = amount.to_le_bytes();
    let mut enc = note_kdf(&ss, b"MUSD-note-enc-v1");
    for i in 0..8 {
        enc[i] ^= amt[i];
    }
    let vt = note_kdf(&ss, b"MUSD-note-vt-v1")[0];
    let cm = note_cm(spk, &ss, amount);
    let mut out = [0u8; PQ_NOTE_BYTES];
    out[0..NOTE_CT_OFF].copy_from_slice(&cm);
    out[NOTE_CT_OFF..NOTE_CT_END].copy_from_slice(&ct);
    out[NOTE_CT_END..NOTE_ENC_END].copy_from_slice(&enc);
    out[NOTE_VT_OFF] = vt;
    Some((out, note_opening(spk, &ss)))
}

/// Recover the amount from a note using `dk` (the recipient's ML-KEM decapsulation secret) and its own spend key `spk`.
/// `Some(amount)` iff the note was sealed to THIS key AND the view-tag + Poseidon `note_cm` binding hold under this
/// recipient's opening; else `None` (a foreign or tampered note is rejected — implicit rejection + the binding check).
pub fn scan_note(note: &[u8], dk_bytes: &[u8], spk: &crate::spend_frontier::Digest4) -> Option<u64> {
    if note.len() != PQ_NOTE_BYTES {
        return None;
    }
    let ss = pqkem::decapsulate(&note[NOTE_CT_OFF..NOTE_CT_END], dk_bytes)?;
    if note_kdf(&ss, b"MUSD-note-vt-v1")[0] != note[NOTE_VT_OFF] {
        return None; // not ours — O(1) view-tag reject
    }
    let ks = note_kdf(&ss, b"MUSD-note-enc-v1");
    let mut amt = [0u8; 8];
    for i in 0..8 {
        amt[i] = note[NOTE_CT_END + i] ^ ks[i];
    }
    let amount = u64::from_le_bytes(amt);
    // Binding: a 1-byte view-tag collision cannot forge a note — recompute the Poseidon commitment.
    if note_cm(spk, &ss, amount) != note[0..NOTE_CT_OFF] {
        return None;
    }
    Some(amount)
}

/// ⭐⭐⭐ THE RECIPIENT'S HALF OF A CONFIDENTIAL NOTE — amount AND the note's SEED, from a note addressed to this `dk`
/// and this `spk`.
///
/// ⛔⛔⛔ WHY THIS IS PUBLIC AND WHY IT IS NOT A TEST HELPER. `scan_note` answers "how much is this worth to
/// me", which is the balance half. SPENDING needs the other half — the note's seed, which the recipient's
/// `NoteOwner { ask, nk, seed }` completes — and without it nothing outside this module could construct a
/// `SpendValidityWitness` for a note it genuinely owns. That gap is exactly why every spend-shaped measurement
/// in this tree ran on `test_spendable_note`, a corpus note planted from a hard-coded witness: a spend of a
/// note nobody was ever paid.
///
/// Returns `(amount, seed)` such that `whir_rec_block::spend_input_leaf` of a witness carrying `value_in = amount` and
/// `owner = NoteOwner { ask, nk, seed }` (the recipient's own `ask`/`nk` behind `spk`) reproduces THIS note's commitment
/// byte-for-byte. DB-395: the seed alone spends nothing — the sender derives it too.
///
/// ⛔ FAIL-CLOSED AND UNCHANGED IN AUTHORITY: it is `scan_note`'s own decapsulate, view-tag and
/// commitment-binding checks — a foreign or tampered note returns `None` here exactly as it does there.
#[must_use]
pub fn open_note(note: &[u8], dk_bytes: &[u8], spk: &crate::spend_frontier::Digest4) -> Option<(u64, crate::spend_frontier::Digest4)> {
    if note.len() != PQ_NOTE_BYTES {
        return None;
    }
    let ss = pqkem::decapsulate(&note[NOTE_CT_OFF..NOTE_CT_END], dk_bytes)?;
    if note_kdf(&ss, b"MUSD-note-vt-v1")[0] != note[NOTE_VT_OFF] {
        return None; // not ours — O(1) view-tag reject
    }
    let ks = note_kdf(&ss, b"MUSD-note-enc-v1");
    let mut amt = [0u8; 8];
    for i in 0..8 {
        amt[i] = note[NOTE_CT_END + i] ^ ks[i];
    }
    let amount = u64::from_le_bytes(amt);
    if note_cm(spk, &ss, amount) != note[0..NOTE_CT_OFF] {
        return None; // the binding must hold, or this is not the note it claims to be
    }
    Some((amount, note_seed_from_ss(&ss)))
}

/// The testnet faucet. It issues valueless test USDm on demand — there is no held pool and nothing to fund: each
/// request seals a fresh confidential note for exactly what it dispenses. A tool-owned demo recipient keypair
/// lets the node `scan_note` what it issued and PROVE the value landed (a real decap, not a counter) — the
/// self-verification path the harness drives without a browser wallet.
pub struct Faucet {
    demo_ek: Vec<u8>,
    /// The demo recipient's OWN notes are found incrementally out of the cover — each issued note is scanned exactly
    /// once, and the balance is an O(1) read (never a re-scan of every note on each call). This is the live wiring of
    /// [`crate::note_scan::IncrementalScanner`] — "find your own tx out of the cover" on the node's self-verify path.
    scanner: crate::note_scan::IncrementalScanner,
    /// DB-395: the demo recipient's spend key `spk = P(ask, nk)` (the secrets behind it are discarded at construction).
    demo_spk: crate::spend_frontier::Digest4,
}

impl Faucet {
    /// Fresh tool-owned demo keypair. No supply is tracked and no value is held — test USDm is issued per request.
    /// DB-395: the demo recipient's spend key comes from a fresh OS-random `(ask, nk)` the node discards — it only ever
    /// SCANS the demo notes (proving arrival), so it holds no spend authority over them either.
    /// `None` when the OS CSPRNG refuses: the faucet assembles NOTHING (`fresh_lc_blind`'s rule) and the RPC layer
    /// answers every faucet route with its refusal — the node itself keeps running.
    pub fn new() -> Option<Self> {
        let (demo_ek, demo_dk) = pqkem::keypair();
        let demo_spk = usdm_decider::whir_rec_block::owner_spk(
            &usdm_decider::whir_rec_block::fresh_lc_blind()?,
            &usdm_decider::whir_rec_block::fresh_lc_blind()?,
        );
        Some(Faucet {
            demo_ek,
            demo_spk,
            scanner: crate::note_scan::IncrementalScanner::new(demo_dk, demo_spk),
        })
    }

    /// The tool-owned demo recipient key — a `drip` with no `to` issues here so the node can scan the landed
    /// balance and prove arrival.
    pub fn demo_ek(&self) -> &[u8] {
        &self.demo_ek
    }

    /// **Issue** `amount` test USDm to `(to_ek, to_spk)` — seals the ordinary 1153-byte confidential note the recipient's
    /// wallet scans and spends (DB-395: committed to the recipient's spend key, so the faucet itself cannot spend it).
    /// Returns the note to record on-chain, or `None` iff `amount == 0` or the KEM fails (fail-closed — never a bad note).
    /// TESTNET-ONLY: the RPC layer gates every call on the testnet network, so this is the test-coin dispenser, never a
    /// mainnet supply path.
    pub fn issue(&self, to_ek: &[u8], to_spk: &crate::spend_frontier::Digest4, amount: u64) -> Option<[u8; PQ_NOTE_BYTES]> {
        if amount == 0 {
            return None;
        }
        seal_note(to_ek, to_spk, amount)
    }

    /// Issue to the tool's own DEMO recipient and retain the note so the node can scan the arrived balance — the
    /// self-verification path the harness drives (no browser wallet needed).
    pub fn issue_to_demo(&mut self, amount: u64) -> Option<[u8; PQ_NOTE_BYTES]> {
        let ek = self.demo_ek.clone();
        let spk = self.demo_spk;
        let note = self.issue(&ek, &spk, amount)?;
        self.scanner.scan_block(std::slice::from_ref(&note)); // find it out of the stream ONCE, incrementally
        Some(note)
    }

    /// The demo recipient's confirmed balance — the incremental scanner already OPENED each forwarded note once (a
    /// real decap, not a counter), so this is an O(1) read of the running total. Proves the testnet USDm landed.
    pub fn demo_balance(&self) -> u64 {
        self.scanner.balance() as u64
    }
}

/// Where a note's ASSET TAG rides inside its 32-byte `enc` field: the amount takes bytes 0..8, the three tag limbs take
/// 8..32 (the wallet's `pq::NOTE_ASSET_OFF`, one spelling on both sides). A USDm note's tag is all-zero, so a note sealed
/// before tags existed decodes as USDm — the wallet's rule, mirrored.
const NOTE_ASSET_OFF: usize = 8;

fn asset_xor(enc: &mut [u8; 32], asset: [u64; 3]) {
    for (i, limb) in asset.iter().enumerate() {
        for (j, byte) in limb.to_le_bytes().iter().enumerate() {
            enc[NOTE_ASSET_OFF + i * 8 + j] ^= *byte;
        }
    }
}

fn asset_from(enc: &[u8], ks: &[u8; 32]) -> [u64; 3] {
    core::array::from_fn(|i| {
        let mut b = [0u8; 8];
        for (j, slot) in b.iter_mut().enumerate() {
            let at = NOTE_ASSET_OFF + i * 8 + j;
            *slot = enc[at] ^ ks[at];
        }
        u64::from_le_bytes(b)
    })
}

/// `asset_note_cm(amount, asset, o)` as 32 bytes, `o = P(spk, seed)` — the one commitment every asset note opens to.
fn note_cm_asset(spk: &crate::spend_frontier::Digest4, ss: &[u8], amount: u64, asset: [u64; 3]) -> [u8; 32] {
    leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(amount, asset, note_opening(spk, ss)))
}

/// ⭐ SATOSHI §8.1 — seal `amount` of `asset` into a confidential note addressed to `(ek, spk)` (ML-KEM-768 and the
/// recipient's spend key), byte-for-byte the wallet's `pq::seal_note_full_asset` layout (`cm ‖ ct ‖ enc ‖ vt`, tag XORed
/// into `enc[8..32]`), and return the note with its OPENING `o = P(spk, seed)` — what a mint carrier opens. ⛔ DB-395: the
/// opening is NOT a spend key — the recipient's `(ask, nk)` behind `spk` is, and the sealer never holds it, so the sealer
/// can neither spend the note nor compute its nullifier.
///
/// `seal_seed`: `None` draws the encapsulation's randomness from the OS (production — DB-382's rule: hiding randomness is
/// never a function of public or node-held data). `Some` makes the encapsulation a pure function of the seed; TEST builds
/// pass the test node's reproducible context so a test chain is the same bytes every run and the cross-run certificate cache
/// can hit (the 2026-10-02 test-speed law). The two differ in one call (`encaps_from_seed` vs `try_encaps`) and nowhere
/// else, so both lay the identical layout.
#[must_use]
pub fn seal_asset_note(
    ek_bytes: &[u8],
    spk: &crate::spend_frontier::Digest4,
    amount: u64,
    asset: [u64; 3],
    seal_seed: Option<[u8; 32]>,
) -> Option<([u8; PQ_NOTE_BYTES], crate::spend_frontier::Digest4)> {
    use fips203::traits::{Encaps as _, SerDes as _};
    let ek = fips203::ml_kem_768::EncapsKey::try_from_bytes(<[u8; 1184]>::try_from(ek_bytes).ok()?).ok()?;
    let (ss, ct) = match seal_seed {
        Some(seed) => ek.encaps_from_seed(&seed),
        None => ek.try_encaps().ok()?,
    };
    let (ss, ct): ([u8; 32], [u8; 1088]) = (ss.into_bytes(), ct.into_bytes());
    let amt = amount.to_le_bytes();
    let mut enc = note_kdf(&ss, b"MUSD-note-enc-v1");
    for i in 0..8 {
        enc[i] ^= amt[i];
    }
    asset_xor(&mut enc, asset);
    let vt = note_kdf(&ss, b"MUSD-note-vt-v1")[0];
    let cm = note_cm_asset(spk, &ss, amount, asset);
    let mut out = [0u8; PQ_NOTE_BYTES];
    out[0..NOTE_CT_OFF].copy_from_slice(&cm);
    out[NOTE_CT_OFF..NOTE_CT_END].copy_from_slice(&ct);
    out[NOTE_CT_END..NOTE_ENC_END].copy_from_slice(&enc);
    out[NOTE_VT_OFF] = vt;
    Some((out, note_opening(spk, &ss)))
}

/// The recipient's side of [`seal_asset_note`]: `(amount, seed, asset tag)` iff the note was sealed to `dk`'s key AND its
/// commitment binds the recovered `(amount, asset)` under THIS recipient's opening `P(spk, seed)` — a flipped tag or
/// amount byte fails the binding and reads as not-ours, never as a re-denominated note (the wallet's
/// `pq::scan_note_full_asset`, mirrored). The seed completes the recipient's `NoteOwner { ask, nk, seed }`.
#[must_use]
pub fn scan_asset_note(note: &[u8], dk_bytes: &[u8], spk: &crate::spend_frontier::Digest4) -> Option<(u64, crate::spend_frontier::Digest4, [u64; 3])> {
    if note.len() != PQ_NOTE_BYTES {
        return None;
    }
    let ss = pqkem::decapsulate(&note[NOTE_CT_OFF..NOTE_CT_END], dk_bytes)?;
    if note_kdf(&ss, b"MUSD-note-vt-v1")[0] != note[NOTE_VT_OFF] {
        return None;
    }
    let ks = note_kdf(&ss, b"MUSD-note-enc-v1");
    let mut amt = [0u8; 8];
    for i in 0..8 {
        amt[i] = note[NOTE_CT_END + i] ^ ks[i];
    }
    let amount = u64::from_le_bytes(amt);
    let asset = asset_from(&note[NOTE_CT_END..NOTE_ENC_END], &ks);
    if note_cm_asset(spk, &ss, amount, asset) != note[0..NOTE_CT_OFF] {
        return None;
    }
    Some((amount, note_seed_from_ss(&ss), asset))
}

/// A reproducible ML-KEM-768 keypair for TEST recipients (FIPS 203 `KeyGen_internal(d, z)` from one seed). Production
/// recipients are the wallet's own scan keys; nothing in the node ever derives a production decapsulation key.
#[must_use]
pub fn kem_keypair_from_seed(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    use fips203::traits::{KeyGen as _, SerDes as _};
    let kdf = |domain: &str| -> [u8; 32] {
        *blake3::Hasher::new_derive_key(domain).update(seed).finalize().as_bytes()
    };
    let (ek, dk) = fips203::ml_kem_768::KG::keygen_from_seed(kdf("MUSD/test-recipient/ml-kem-768/d/v1"), kdf("MUSD/test-recipient/ml-kem-768/z/v1"));
    (ek.into_bytes().to_vec(), dk.into_bytes().to_vec())
}

/// ⭐ DB-395 — what a RECIPIENT holds to open and spend its notes: the ML-KEM decapsulation key and the spend secrets
/// `(ask, nk)` behind its address's `spk`. A WALLET-side value: the node holds none of a user's. The in-process harness paths
/// (`Node::build_sat_bond_from_reward`, the pins) take it exactly as a wallet would hold it.
pub struct RecipientSecrets {
    pub dk: Vec<u8>,
    pub ask: crate::spend_frontier::Digest4,
    pub nk: crate::spend_frontier::Digest4,
}

impl RecipientSecrets {
    /// The address spend key `spk = P(ask, nk)`.
    #[must_use]
    pub fn spk(&self) -> crate::spend_frontier::Digest4 {
        usdm_decider::whir_rec_block::owner_spk(&self.ask, &self.nk)
    }
    /// Open an asset note sealed to this recipient: `(amount, owner, asset)`, the owner ready for an input witness.
    #[must_use]
    pub fn open_asset(&self, note: &[u8]) -> Option<(u64, usdm_decider::whir_rec_block::NoteOwner, [u64; 3])> {
        let (amount, seed, asset) = scan_asset_note(note, &self.dk, &self.spk())?;
        Some((amount, usdm_decider::whir_rec_block::NoteOwner { ask: self.ask, nk: self.nk, seed }, asset))
    }
    /// A reproducible TEST recipient from one seed — the same keys `satoshi::RewardRecipient::for_test(seed)` seals to.
    #[must_use]
    pub fn for_test(seed: &[u8; 32]) -> RecipientSecrets {
        let (_ek, dk) = kem_keypair_from_seed(seed);
        let (ask, nk) = crate::satoshi::RewardRecipient::test_spend_secrets(seed);
        RecipientSecrets { dk, ask, nk }
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {

    /// ⭐⭐⭐ A DRIPPED NOTE IS SPENDABLE BY ITS RECIPIENT — the loop every settlement measurement needs.
    ///
    /// ⛔⛔⛔ WHAT WAS NEVER PINNED. The faucet seals a note to an ML-KEM key and `scan_note` proves the
    /// recipient can read its AMOUNT. Nothing proved the recipient could SPEND it: that needs the per-note
    /// Poseidon secret, and the only thing in this tree that ever produced a spendable note was
    /// `Node::test_spendable_note`, a corpus note planted FROM a hard-coded witness. Every spend-shaped
    /// measurement therefore spent a note nobody was ever paid — the value path and the spend path were
    /// never joined.
    ///
    /// This joins them, at the one place they meet: the note's COMMITMENT. `open_note` recovers
    /// `(amount, sk)` by the recipient's own decapsulation, and the production prover's own statement of
    /// the spent leaf — `whir_rec_block::spend_input_leaf`, which exists precisely so nobody re-derives a
    /// commitment by hand — must reproduce the note's first 32 bytes EXACTLY. If it does, a real user can
    /// spend what the faucet paid them; if it drifts by one byte the note is money that can never move.
    ///
    /// ⭐ THE CONTROL IS THE SECOND HALF, NOT AN AFTERTHOUGHT: a note sealed to a DIFFERENT key must
    /// return `None`, or "it opened" would prove nothing about ownership.
    #[test]
    fn a_dripped_note_is_spendable_by_its_recipient() {
        let seed = [0xD1; 32];
        let (ek, _) = super::kem_keypair_from_seed(&seed);
        let recipient = super::RecipientSecrets::for_test(&seed);
        let spk = recipient.spk();
        let amount = 4_242u64 + usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC; // §BR-14: the spend below pays the fee
        let note = super::seal_note(&ek, &spk, amount).expect("the faucet seals a note to this address");

        let (got_amount, note_seed) = super::open_note(&note, &recipient.dk, &spk).expect(
            "⛔ the RECIPIENT cannot open a note addressed to them — a note whose opening its owner \
             cannot derive is money that can never move",
        );
        assert_eq!(got_amount, amount, "the opened amount must be what was sealed");

        // The production prover's OWN statement of the spent leaf, from a witness carrying exactly what
        // the recipient holds: its `(ask, nk)` and the seed it recovered. Nothing here recomputes a commitment by hand.
        let owner = usdm_decider::whir_rec_block::NoteOwner { ask: recipient.ask, nk: recipient.nk, seed: note_seed };
        let w = usdm_decider::whir_rec_block::SpendValidityWitness {
            value_in: got_amount,
            owner,
            value_out: (got_amount - 100) - 99900,
            fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
            lc_blind: crate::spend_frontier::TEST_LC_BLIND,
            out0_value: (got_amount - 150) - 99900,
            out0_opening: owner.opening(),
            out1_value: 50,
            out1_opening: owner.opening(),
        };
        let leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w)
            .expect("the production prover states the spent note's leaf for a well-formed witness");
        assert_eq!(
            crate::spend_frontier::leaf_to_cm_bytes(leaf).as_slice(),
            &note[..32],
            "⛔⛔⛔ THE FAUCET'S NOTE AND THE SPEND PROVER DISAGREE ON ITS COMMITMENT. The recipient holds \
             a note the spend circuit cannot name, so the drip credits money that can never be spent — and \
             every spend measurement in this tree would keep running on corpus notes nobody was paid."
        );

        // CONTROL: a note sealed to someone else must not open here, or ownership means nothing.
        let other = super::RecipientSecrets::for_test(&[0xD2; 32]);
        let (other_ek, _) = super::kem_keypair_from_seed(&[0xD2; 32]);
        let foreign = super::seal_note(&other_ek, &other.spk(), amount).expect("seal to a different address");
        assert!(
            super::open_note(&foreign, &recipient.dk, &spk).is_none(),
            "⛔ a note addressed to ANOTHER key opened with ours — the view-tag and commitment binding \
             are what make this ownership rather than a guess"
        );
    }
    use super::*;

    #[test]
    fn seal_scan_roundtrip_and_reject_wrong_key_and_tamper() {
        let seed = [0xD3; 32];
        let (ek, _) = kem_keypair_from_seed(&seed);
        let r = RecipientSecrets::for_test(&seed);
        let spk = r.spk();
        let note = seal_note(&ek, &spk, 250_000).expect("seal");
        assert_eq!(
            scan_note(&note, &r.dk, &spk),
            Some(250_000),
            "recipient recovers the exact amount"
        );

        // A DIFFERENT key cannot open it (implicit rejection + view-tag/binding) — adversarial reject.
        let (_ek2, dk2) = kem_keypair_from_seed(&[0xD4; 32]);
        assert_eq!(
            scan_note(&note, &dk2, &spk),
            None,
            "not-the-recipient must not open"
        );
        // ⛔ DB-395: the right decapsulation key under ANOTHER spend key does not open it either — the commitment binds the
        // recipient's spend key, so a note sealed to one address is never read as another's.
        let other_spk = RecipientSecrets::for_test(&[0xD4; 32]).spk();
        assert_eq!(scan_note(&note, &r.dk, &other_spk), None, "⛔ a note opened under a spend key it was not sealed to");

        // A TAMPERED enc_amount byte fails the note_cm binding — adversarial reject.
        let mut bad = note;
        bad[NOTE_CT_END] ^= 0x01;
        assert_eq!(scan_note(&bad, &r.dk, &spk), None, "tampered amount must reject");
    }

    // CORRECT-ARCHITECTURE-REVIEWED: the conservation-forward model (held / available / forward / receive) is
    // REPLACED by the testnet-mint model per user 2026-07-20 ("the faucet should automatically create test tokens
    // out of thin air, it should not require you to fund it"). The retired available()==0 / over-draw-fail-closed
    // assertions tested methods that no longer exist; this mint-model test is stronger on what actually matters —
    // issued value lands in a real decap-able balance, a zero-amount request fail-closes, and a note issued to a
    // foreign key adversarially rejects under the demo key. TESTNET-ONLY creation stays gated at the RPC layer.
    #[test]
    fn faucet_issues_test_usdm_on_demand_and_it_lands() {
        let mut f = Faucet::new().expect("the OS CSPRNG draws the test faucet's key");
        assert_eq!(
            f.demo_balance(),
            0,
            "nothing issued yet — no held pool, no allocation"
        );

        // Issue twice to the demo recipient; the node decaps both and the real balance lands (a scan, not a tally).
        f.issue_to_demo(300).expect("issue 300");
        f.issue_to_demo(200).expect("issue 200");
        assert_eq!(
            f.demo_balance(),
            500,
            "issued test USDm actually lands in a real, decap-able balance"
        );

        // Fail-closed on a zero-amount request — never a bad/empty note.
        let demo_ek = f.demo_ek().to_vec();
        let demo_spk = f.demo_spk;
        assert!(
            f.issue(&demo_ek, &demo_spk, 0).is_none(),
            "a zero-amount request is rejected"
        );

        // Isolation (adversarial): a note issued to a FOREIGN wallet key must NOT open under the demo scanner — feeding
        // it to the live incremental scanner yields no match and leaves the balance unchanged (no false positive).
        let (user_ek, _user_dk) = kem_keypair_from_seed(&[0xD5; 32]);
        let user_spk = RecipientSecrets::for_test(&[0xD5; 32]).spk();
        let foreign = f.issue(&user_ek, &user_spk, 999).expect("issue to a user key");
        assert_eq!(
            f.scanner.scan_block(std::slice::from_ref(&foreign)),
            0,
            "the demo scanner cannot open a user's note"
        );
        assert_eq!(
            f.demo_balance(),
            500,
            "a foreign note never inflates the demo balance"
        );
    }

    /// SATOSHI §8.1 parity: a SAT note the node seals scans to exactly `(amount, SAT tag, seed)` under the recipient's keys, its
    /// commitment is `asset_note_cm(amount, SAT, P(spk, seed))` (what the mint carrier opens), a stranger's key reads nothing,
    /// and a flipped TAG byte fails the binding (never a re-denominated note). A seeded seal is the same bytes twice; two
    /// OS-random seals differ (hiding randomness is drawn, not derived). DB-395: what the sealer gets back is the OPENING,
    /// which is not the recipient's spend key.
    #[test]
    fn a_sat_note_sealed_by_the_node_scans_to_its_amount_tag_and_key_and_a_flipped_tag_fails_the_binding() {
        let (ek, dk) = kem_keypair_from_seed(&[7u8; 32]);
        let spk = RecipientSecrets::for_test(&[7u8; 32]).spk();
        let (_ek2, dk2) = kem_keypair_from_seed(&[8u8; 32]);
        let tag = crate::satoshi::asset_tag();
        let (note, opening) = seal_asset_note(&ek, &spk, 4_159_090, tag, None).expect("seals");
        let (amount, seed_back, asset) = scan_asset_note(&note, &dk, &spk).expect("the recipient scans its note");
        assert_eq!((amount, asset), (4_159_090, tag), "amount and asset recovered");
        assert_eq!(
            usdm_decider::whir_rec_block::owner_opening(&spk, &seed_back),
            opening,
            "the recipient re-derives the opening the sealer committed to"
        );
        assert_eq!(&note[..32], &leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(4_159_090, tag, opening)), "cm = asset_note_cm");
        assert!(scan_asset_note(&note, &dk2, &spk).is_none(), "⛔ a stranger's key opened the note");
        assert!(scan_note(&note, &dk, &spk).is_none(), "CALIBRATION: the USDm-only scanner refuses a SAT note (its binding is under the SAT tag)");
        let mut flipped = note;
        flipped[NOTE_CT_END + NOTE_ASSET_OFF] ^= 1;
        assert!(scan_asset_note(&flipped, &dk, &spk).is_none(), "⛔ a flipped asset byte scanned as a note of another asset");
        let a = seal_asset_note(&ek, &spk, 5, tag, Some([3u8; 32])).expect("seals");
        let b = seal_asset_note(&ek, &spk, 5, tag, Some([3u8; 32])).expect("seals");
        assert_eq!(a.0.to_vec(), b.0.to_vec(), "a seeded seal is reproducible (test chains are the same bytes every run)");
        let c = seal_asset_note(&ek, &spk, 5, tag, None).expect("seals");
        let d = seal_asset_note(&ek, &spk, 5, tag, None).expect("seals");
        assert_ne!(c.0.to_vec(), d.0.to_vec(), "⛔ two OS-random seals of one amount shared bytes");
    }
}
