// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §BR-5 — THE CASH-OUT TICKET: a cash-out piece's destination, its release height and its redeem blind, encrypted under a
//! per-ticket key `K` whose Shamir shares (`shamir`, t = ⌈2n/3⌉) ride the custodians' legs
//! (docs/BR-5-CASHOUT-TICKETS-SPEC-20261029.md). The ticket is public and CONSTANT width (`TICKET_BYTES`), whatever the
//! address; it is bound to the attested burn by `peg::redeem_commit(address, pay_after, blind)`, so a ticket that decrypts to
//! anything else — a swapped ciphertext, a key reconstructed from too few shares — pays nothing.
//!
//! Cipher: a blake3 XOF keystream keyed with `K` (domain-separated) XORed over the fixed-width plaintext — the stream cipher
//! shape (one key, one message: `K` is fresh per ticket and never reused). Post-quantum: a 256-bit symmetric key.
//! DIGITAL-CASH-PRIVACY-REVIEWED: ciphertext of one fixed width; the plaintext is readable only with ≥ t shares.

use crate::spend_frontier::{digest_from_lane_bytes, digest_to_lane_bytes, Digest4, DIGEST_LANE_BYTES};

/// The widest payable destination (`peg_attest::PEG_ATTEST_ADDRESS_MAX`).
pub const TICKET_ADDRESS_MAX: usize = crate::peg_attest::PEG_ATTEST_ADDRESS_MAX;
/// `len (2 LE) ‖ address padded to TICKET_ADDRESS_MAX ‖ pay_after (8 LE) ‖ blind (lane bytes)`.
pub const TICKET_BYTES: usize = 2 + TICKET_ADDRESS_MAX + 8 + DIGEST_LANE_BYTES;

fn keystream(key: &[u8; 32]) -> [u8; TICKET_BYTES] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"MUSD/cashout-ticket/stream/v1");
    let mut out = [0u8; TICKET_BYTES];
    h.finalize_xof().fill(&mut out);
    out
}

/// Encrypt a piece's destination under `key`. `None` for an empty or over-wide address.
#[must_use]
pub fn seal(key: &[u8; 32], address: &[u8], pay_after: u64, blind: &Digest4) -> Option<[u8; TICKET_BYTES]> {
    if address.is_empty() || address.len() > TICKET_ADDRESS_MAX {
        return None;
    }
    let mut pt = [0u8; TICKET_BYTES];
    pt[..2].copy_from_slice(&(address.len() as u16).to_le_bytes());
    pt[2..2 + address.len()].copy_from_slice(address);
    pt[2 + TICKET_ADDRESS_MAX..10 + TICKET_ADDRESS_MAX].copy_from_slice(&pay_after.to_le_bytes());
    pt[10 + TICKET_ADDRESS_MAX..].copy_from_slice(&digest_to_lane_bytes(blind));
    let ks = keystream(key);
    for (p, k) in pt.iter_mut().zip(ks.iter()) {
        *p ^= k;
    }
    Some(pt)
}

/// Decrypt a ticket and accept it ONLY if it opens `redeem_commit` (the attested burn's destination commitment): the address,
/// the release height and the blind. `None` for a ticket that decrypts to anything that does not open it.
#[must_use]
pub fn open_bound(key: &[u8; 32], ticket: &[u8; TICKET_BYTES], redeem_commit: &[u8; 32]) -> Option<(Vec<u8>, u64, Digest4)> {
    let ks = keystream(key);
    let mut pt = [0u8; TICKET_BYTES];
    for (i, p) in pt.iter_mut().enumerate() {
        *p = ticket[i] ^ ks[i];
    }
    let len = u16::from_le_bytes([pt[0], pt[1]]) as usize;
    if len == 0 || len > TICKET_ADDRESS_MAX || pt[2 + len..2 + TICKET_ADDRESS_MAX].iter().any(|b| *b != 0) {
        return None;
    }
    let address = pt[2..2 + len].to_vec();
    let pay_after = u64::from_le_bytes(pt[2 + TICKET_ADDRESS_MAX..10 + TICKET_ADDRESS_MAX].try_into().ok()?);
    let blind = digest_from_lane_bytes(&pt[10 + TICKET_ADDRESS_MAX..])?;
    (crate::peg::redeem_commit(&address, pay_after, &blind) == *redeem_commit).then_some((address, pay_after, blind))
}

/// ⭐⭐⭐ §BR-5 — THE BURN IS BOUND TO ITS DESTINATION. The burned output's opening is derived from the ticketed redeem
/// commitment (`cm_bytes_to_leaf(H(domain ‖ commit))`, the delegation burn's shape), so the burn carrier — which only the note's
/// owner can prove — fixes the ticket, its share commitments and through them the destination. A copied request carrying
/// another ticket, or a proposer that swaps the ticket or the shares, names another commitment, and the burned output no longer
/// opens: every proposer, attestor and publisher refuses it. (Before this, nothing tied the destination to the owner's proof:
/// the sealed address was the requester's or proposer's word.)
///
/// ⛔ AND THE OPENING IS NOT PUBLIC. It also takes the piece's LEG BLIND — the secret every custodian's sealed leg and request
/// envelope carry (and the requester's own node returns to its wallet), never on the chain. Derived from the ticketed
/// commitment alone (as first built), anyone holding the object could test the few ladder burn amounts against `out0_cm`
/// and read each piece's size; with the leg blind mixed in, only the custodians (who see the amount in their legs anyway) can.
/// The binding is unchanged: another ticket is another commitment, whatever the blind.
#[must_use]
pub fn burn_out_opening(ticketed_commit: &[u8; 32], leg_blind: &Digest4) -> Digest4 {
    let mut pre = Vec::with_capacity(20 + 32 + DIGEST_LANE_BYTES);
    pre.extend_from_slice(b"MUSD/cashout-burn/v2");
    pre.extend_from_slice(ticketed_commit);
    pre.extend_from_slice(&digest_to_lane_bytes(leg_blind));
    crate::spend_frontier::cm_bytes_to_leaf(crate::hash::Hash32::hash(&pre).as_bytes())
}

/// ⭐ §18.14 — [`burn_out_cm`] for a coin note's burn: the burned output carries the coin's own asset. `coin` 0 is USDm.
#[must_use]
pub fn burn_out_cm_of(coin: u32, burn: u64, redeem_commit: &[u8; 32], leg_blind: &crate::spend_frontier::Digest4) -> crate::spend_frontier::Digest4 {
    if coin == 0 {
        return burn_out_cm(burn, redeem_commit, leg_blind);
    }
    usdm_decider::whir_rec_block::asset_note_cm(burn, usdm_decider::whir_rec_block::wrapped_asset_tag_u32(coin), burn_out_opening(redeem_commit, leg_blind))
}

/// The burned output's commitment a burn of `burn` USDm bound to `ticketed_commit` (under the piece's leg blind) must carry.
#[must_use]
pub fn burn_out_cm(burn: u64, ticketed_commit: &[u8; 32], leg_blind: &Digest4) -> Digest4 {
    usdm_decider::whir_rec_block::asset_note_cm(burn, usdm_decider::whir_rec_block::USDM_ASSET_TAG, burn_out_opening(ticketed_commit, leg_blind))
}

/// `len` bytes of OS entropy (the system RNG through the decider's `fresh_lc_blind`, expanded by a blake3 XOF over two fresh
/// draws). `None` when the OS gives none — a requester then refuses the cash-out rather than seal under a guessable key.
#[must_use]
pub fn fresh_entropy(len: usize) -> Option<Vec<u8>> {
    let a = usdm_decider::whir_rec_block::fresh_lc_blind()?;
    let b = usdm_decider::whir_rec_block::fresh_lc_blind()?;
    let mut h = blake3::Hasher::new_derive_key("MUSD/cashout-ticket/entropy/v1");
    h.update(&digest_to_lane_bytes(&a));
    h.update(&digest_to_lane_bytes(&b));
    let mut out = vec![0u8; len];
    h.finalize_xof().fill(&mut out);
    Some(out)
}

/// The leg's destination-kind marker for a ticketed peg-out (the leg names no address; this is all a custodian needs to
/// price the release: a Monero piece releases the burn, a Bitcoin piece the chain's priced ladder unit).
pub const KIND_BTC: &str = "ticket:btc";
pub const KIND_XMR: &str = "ticket:xmr";
/// ⭐ §18.14 — a coin note's burn: it pays atom for atom from its own coin ledger, never a dollar's worth from a bridge ledger.
pub const KIND_COIN_BTC: &str = "ticket:coin:btc";
pub const KIND_COIN_XMR: &str = "ticket:coin:xmr";

/// ⭐ §BR-9a step (c) — the request envelope's address slot for a redeem: the destination KIND marker alone (no address: the
/// address is in the ticket; no key share: the ticket key is encapsulated once to the epoch key, `epoch_release::seal_ticket`).
#[must_use]
pub fn request_slot(monero: bool) -> String {
    (if monero { KIND_XMR } else { KIND_BTC }).to_string()
}

/// The coin ledger a request slot burns from, if it is a coin note's burn.
#[must_use]
pub fn coin_ledger_of(slot: &str) -> Option<u32> {
    match slot {
        KIND_COIN_BTC => Some(crate::peg::COIN_BTC_ASSET_ID),
        KIND_COIN_XMR => Some(crate::peg::COIN_XMR_ASSET_ID),
        _ => None,
    }
}

/// The reader paired with [`request_slot`]: is the piece owed in Monero?
#[must_use]
pub fn parse_request_slot(slot: &str) -> Option<bool> {
    match slot {
        KIND_BTC | KIND_COIN_BTC => Some(false),
        KIND_XMR | KIND_COIN_XMR => Some(true),
        _ => None,
    }
}

/// ⭐ §BR-9a step (c) — what the ticketed commitment binds in place of the per-ticket share commitments: the hash of the ONE
/// epoch ciphertext, so a relay that swaps the ciphertext voids the payout (spec §19.3).
#[must_use]
pub fn ct_commits(ct: &[u8]) -> [[u8; 32]; 1] {
    [*blake3::hash(ct).as_bytes()]
}

/// ⭐ THE TICKETED REDEEM COMMITMENT the quorum signs: the destination commitment (`peg::redeem_commit(address, pay_after,
/// blind)`) bound to the ticket's bytes and the epoch ciphertext's hash — so a relay that swaps the ticket or the ciphertext
/// voids the payout, and the signed statement needs no new field.
#[must_use]
pub fn ticketed_commit(inner: &[u8; 32], ticket: &[u8], ct_commits: &[[u8; 32]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/cashout-ticket/ticketed-commit/v1");
    h.update(inner);
    h.update(&(ticket.len() as u64).to_le_bytes());
    h.update(ticket);
    h.update(&(ct_commits.len() as u64).to_le_bytes());
    for c in ct_commits {
        h.update(c);
    }
    *h.finalize().as_bytes()
}

/// Open a ticket with a reconstructed key and accept it only if it opens the object's TICKETED commitment.
#[must_use]
pub fn open_ticketed(
    key: &[u8; 32],
    ticket: &[u8],
    ct_commits: &[[u8; 32]],
    redeem_commit: &[u8; 32],
) -> Option<(Vec<u8>, u64, Digest4)> {
    let t: &[u8; TICKET_BYTES] = ticket.try_into().ok()?;
    let ks = keystream(key);
    let mut pt = [0u8; TICKET_BYTES];
    for (i, p) in pt.iter_mut().enumerate() {
        *p = t[i] ^ ks[i];
    }
    let len = u16::from_le_bytes([pt[0], pt[1]]) as usize;
    if len == 0 || len > TICKET_ADDRESS_MAX || pt[2 + len..2 + TICKET_ADDRESS_MAX].iter().any(|b| *b != 0) {
        return None;
    }
    let address = pt[2..2 + len].to_vec();
    let pay_after = u64::from_le_bytes(pt[2 + TICKET_ADDRESS_MAX..10 + TICKET_ADDRESS_MAX].try_into().ok()?);
    let blind = digest_from_lane_bytes(&pt[10 + TICKET_ADDRESS_MAX..])?;
    let inner = crate::peg::redeem_commit(&address, pay_after, &blind);
    (ticketed_commit(&inner, ticket, ct_commits) == *redeem_commit).then_some((address, pay_after, blind))
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ⭐⭐ §19.4 — THE STAGED NOTE'S ONE-TIME KEY: a cash-out piece is first staged as an ordinary payment to the wallet's own scan
// key under a one-time spend key derived from a key `K` the wallet re-derives from its 24 words (no ordinary send selects
// it); the wallet then proves the anonymous claim of that note itself. (Until §19.4 the key was the B5-d escrow's, which
// custody reconstructed to burn the note — and so knew which note it was; that escrow and its envelope are deleted.)
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

pub fn escrow_key_part(key: &[u8; 32], part: &[u8]) -> Digest4 {
    let mut h = blake3::Hasher::new_derive_key("MUSD/cashout-escrow/keys/v1");
    h.update(part);
    h.update(key);
    crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes())
}

/// The escrow note's owner: its spend and nullifier keys derived from the ticket key, its seed from the note itself.
#[must_use]
pub fn escrow_owner(key: &[u8; 32], seed: &Digest4) -> usdm_decider::whir_rec_block::NoteOwner {
    usdm_decider::whir_rec_block::NoteOwner { ask: escrow_key_part(key, b"ask"), nk: escrow_key_part(key, b"nk"), seed: *seed }
}

/// The escrow note's address spend key (`spk = P(ask, nk)`): what the wallet seals the escrow note to.
#[must_use]
pub fn escrow_spk(key: &[u8; 32]) -> Digest4 {
    usdm_decider::whir_rec_block::owner_spk(&escrow_key_part(key, b"ask"), &escrow_key_part(key, b"nk"))
}

/// The escrow note's commitment for `value` under `key` and `seed`.
#[must_use]
pub fn escrow_cm(key: &[u8; 32], value: u64, seed: &Digest4) -> Digest4 {
    usdm_decider::whir_rec_block::asset_note_cm(value, usdm_decider::whir_rec_block::USDM_ASSET_TAG, escrow_owner(key, seed).opening())
}


/// The escrow note's nullifier in its canonical 32-byte form (the request's id: what the burn will spend).
#[must_use]
pub fn escrow_nf(key: &[u8; 32], value: u64, seed: &Digest4) -> [u8; 32] {
    crate::spend_frontier::leaf_to_cm_bytes(escrow_owner(key, seed).nullifier(&escrow_cm(key, value, seed)))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::{combine, split, two_thirds_threshold};

    /// ⭐ §BR-5 — A TICKET OPENS ONLY WITH THE THRESHOLD OF SHARES AND ONLY TO THE ATTESTED DESTINATION.
    /// A ticket for a Bitcoin address under a key split 5-of-7 (t = ⌈2·7/3⌉): five shares reconstruct the key and the ticket
    /// opens to the address, height and blind that open `redeem_commit`. TAMPERS: four shares reconstruct a key that opens
    /// nothing; a ciphertext swapped for another address's ticket (under the same key) does not open the burn's commitment; a
    /// flipped ciphertext byte opens nothing. CENSUS: every ticket is `TICKET_BYTES` long whatever the address length.
    /// TWO-PARTY-REVIEWED: this pins the codec and its binding, a pure function of its inputs; the crossing (shares held by
    /// separate custodian nodes, released at the batch, reconstructed on another node that then pays) is the B5-c lane pin.
    #[test]
    fn a_ticket_opens_only_with_the_threshold_and_only_to_the_attested_destination() {
        let key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(3));
        let blind = usdm_decider::poseidon2_compress::lanes_of(&[0x7c, 1, 2, 3]);
        let addr = b"tb1qexampleaddressforthecashoutticket00000000".to_vec();
        let commit = crate::peg::redeem_commit(&addr, 4_242, &blind);
        let ticket = seal(&key, &addr, 4_242, &blind).expect("seals");
        assert_eq!(ticket.len(), TICKET_BYTES);
        let t = two_thirds_threshold(7);
        assert_eq!(t, 5);
        let coeffs: Vec<u8> = (0..(t - 1) * 32).map(|i| (i as u8).wrapping_mul(61).wrapping_add(17)).collect();
        let shares = split(&key, t, 7, &coeffs).expect("splits");
        let k5: [u8; 32] = combine(&shares[2..7]).expect("combines").try_into().expect("32");
        assert_eq!(open_bound(&k5, &ticket, &commit), Some((addr.clone(), 4_242, blind)), "five shares open the ticket");
        let k4: [u8; 32] = combine(&shares[..4]).expect("combines").try_into().expect("32");
        assert_eq!(open_bound(&k4, &ticket, &commit), None, "⛔ four shares (below two thirds) opened the ticket");
        let other = seal(&key, b"tb1qthethiefsaddress", 4_242, &blind).expect("seals");
        assert_eq!(open_bound(&key, &other, &commit), None, "⛔ a swapped ticket opened the burn's commitment");
        let mut flipped = ticket;
        flipped[5] ^= 1;
        assert_eq!(open_bound(&key, &flipped, &commit), None, "⛔ a flipped ticket byte opened");
        assert_eq!(seal(&key, b"x", 0, &blind).expect("seals").len(), seal(&key, &[b'y'; TICKET_ADDRESS_MAX], 0, &blind).expect("seals").len(), "one width");
        assert!(seal(&key, &[b'z'; TICKET_ADDRESS_MAX + 1], 0, &blind).is_none() && seal(&key, b"", 0, &blind).is_none(), "bounds refused");
    }

    /// ⭐ §BR-5 — A REQUESTER'S TICKET OPENS ONLY FROM TWO THIRDS OF ITS SHARES, AND A SWAPPED TICKET OR SHARE COMMITMENT VOIDS IT.
    /// `build` for 7 custodians: any 5 shares (each matching its public commitment) reconstruct the key and the ticket opens the
    /// ticketed commitment to the address, height and blind; 4 do not. TAMPERS: a share that is not its commitment's; a ticket
    /// swapped for another address's under the same key; a share-commitment list with one entry changed; the slot codec refuses
    /// a zero x and a short share.
    /// TWO-PARTY-REVIEWED: the codec and binding, a pure function; the crossing is the node pin
    /// `a_ticketed_cash_out_pays_only_after_two_thirds_of_custody_release_their_shares`.
    /// ⭐ §BR-5 — THE BURN AMOUNT IS NOT READABLE FROM THE CHAIN. An observer holds the object's ticketed commitment and the
    /// burned output's commitment and tries every ladder burn under every opening it can derive from public bytes (the
    /// commitment alone — the first build's derivation — or with an all-zero blind): none opens. CALIBRATION: a custodian
    /// holding the piece's leg blind finds the burn exactly, and the commitment differs per blind (the blind is load-bearing).
    #[test]
    fn a_burns_amount_cannot_be_read_from_its_ticketed_commitment_without_the_leg_blind() {
        let tc = [0x5Eu8; 32];
        let leg = crate::spend_frontier::cm_bytes_to_root(&crate::spend_frontier::canonical_filler_bytes(0x6b)).unwrap();
        let burn: u64 = 25_000_000;
        let out0 = burn_out_cm(burn, &tc, &leg);
        let public_only = |c: &[u8; 32]| {
            let mut pre = Vec::new();
            pre.extend_from_slice(b"MUSD/cashout-burn/v1");
            pre.extend_from_slice(c);
            crate::spend_frontier::cm_bytes_to_leaf(crate::hash::Hash32::hash(&pre).as_bytes())
        };
        let candidates: Vec<u64> = (1..=2_000u64).map(|k| k * 50_000).chain(crate::peg_pool::PAYOUT_DENOMS.iter().copied()).collect();
        assert!(candidates.contains(&burn), "CALIBRATION: the true burn is among the observer's candidates");
        let zero = usdm_decider::poseidon2_compress::zero_digest();
        for v in &candidates {
            let tag = usdm_decider::whir_rec_block::USDM_ASSET_TAG;
            assert_ne!(usdm_decider::whir_rec_block::asset_note_cm(*v, tag, public_only(&tc)), out0, "⛔ the burn amount {v} was read from public bytes alone");
            assert_ne!(burn_out_cm(*v, &tc, &zero), out0, "⛔ the burn amount {v} was read under a guessable blind");
        }
        let found: Vec<u64> = candidates.iter().copied().filter(|v| burn_out_cm(*v, &tc, &leg) == out0).collect();
        assert_eq!(found, vec![burn], "CALIBRATION: the leg blind's holder reads exactly the burn");
        assert_ne!(burn_out_cm(burn, &tc, &zero), out0, "CALIBRATION: the blind changes the commitment");
    }

    /// ⭐ §BR-9a step (c) — A TICKETED REDEEM OPENS ONLY UNDER ITS EPOCH'S RELEASED KEY, AND A SWAPPED CIPHERTEXT VOIDS IT.
    /// A ticket sealed to an epoch key (`epoch_release::seal_ticket`) opens with that epoch's secret to the address, height and
    /// blind of the ticketed commitment, and yields the wallet's message `m` (the escrow key). TAMPERS: another epoch's secret
    /// opens nothing; a ciphertext swapped for one sealing another key (same epoch) does not open the ticketed commitment; a
    /// ticket swapped for another address's under the same key does not open it; the kind slot refuses anything else.
    /// TWO-PARTY-REVIEWED: the codec and binding, a pure function; the crossing (shares released between custodian nodes at the
    /// batch, the ticket opened on another node that then pays) is the node pin `br9a_c_a_ticket_pays_only_after_its_epoch_is_released`.
    #[test]
    fn a_ticketed_redeem_opens_only_under_its_epoch_key_and_a_swapped_ciphertext_voids_it() {
        let keypair = |tag: u8| {
            let seed = crate::epoch_deal_tx::matrix_seed(u64::from(tag));
            let (sec, part) = crate::epoch_key::deal(&seed, &[tag; 32]);
            (crate::epoch_key::combine_public(&seed, &[part]), crate::epoch_key::secret_from(&[sec]))
        };
        let (pk, sk) = keypair(3);
        let (pk2, sk2) = keypair(4);
        let m = [0x4eu8; 32];
        let blind = usdm_decider::poseidon2_compress::lanes_of(&[0x7d, 1, 2, 3]);
        let addr = b"tb1qticketedcashoutdestination0000000".to_vec();
        let (key, ct, ticket, tc) = crate::epoch_release::seal_ticket(&pk, &m, &addr, 77, &blind).expect("seals");
        assert_eq!((ct.len(), ticket.len()), (crate::epoch_key::CT_BYTES, TICKET_BYTES), "one ciphertext, one ticket width");
        assert_eq!(crate::epoch_key::decapsulate_message(&pk, &sk, &ct), Some((m, key)), "the epoch secret yields m and K");
        assert_eq!(open_ticketed(&key, &ticket, &ct_commits(&ct), &tc), Some((addr.clone(), 77, blind)), "the ticket opens");
        assert_eq!(crate::epoch_key::decapsulate(&pk2, &sk2, &ct), None, "⛔ another epoch's secret opened the ciphertext");
        let (k_other, ct_other, _, _) = crate::epoch_release::seal_ticket(&pk, &[0x4fu8; 32], &addr, 77, &blind).expect("seals");
        assert_eq!(open_ticketed(&k_other, &ticket, &ct_commits(&ct_other), &tc), None, "⛔ a swapped ciphertext kept the ticket open");
        let other = seal(&key, b"tb1qthethief", 77, &blind).expect("seals").to_vec();
        assert_eq!(open_ticketed(&key, &other, &ct_commits(&ct), &tc), None, "⛔ a swapped ticket opened the ticketed commitment");
        assert_eq!((parse_request_slot(&request_slot(true)), parse_request_slot(&request_slot(false))), (Some(true), Some(false)));
        assert!(parse_request_slot("ticket:btc|share:1:00").is_none() && parse_request_slot("").is_none(), "bad slots refused");
    }

}
