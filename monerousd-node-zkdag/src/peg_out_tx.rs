// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ §CS-b — THE PEG-OUT IS A CHAIN OBJECT, BECAUSE IT DESTROYS USDm AND HANDS BACK RESERVE.
//!
//! ROOT-LAYER: the mirror of `peg_in_tx`. A holder burns USDm and redeems BTC/XMR; the burn must retire
//! on every node and the reserve reduction must advance on every node. Before this class,
//! `Node::execute_peg_out_burn_verified` credited the change note through `record_note_payload` and
//! `peg::peg_out_confidential` advanced `reserve_commit` / `minted_commit` + inserted the nullifier into
//! `spent_burns` — all on the ONE node that answered the RPC.
//!
//! ## Why the local mutation was a funds hole in BOTH directions
//! 1. **THE BURN DOES NOT TRAVEL.** `spent_burns` is per-node, so the same USDm note redeems again on
//!    every other node — the reserve is drained once per node by one burn.
//! 2. **THE CHANGE NOTE EXISTS ON ONE MACHINE.** The redeemer's change is credited locally, so every peer
//!    holds nothing for it.
//!
//! Same cardinal, same shape, same fix as the peg-in beside it: the object carries exactly what
//! `peg::peg_out_confidential` decides on, so every peer re-runs THAT function — same
//! `peg_out_confidential_msg` domain, same `spent_burns` replay key, same redeem-floor carrier.

use crate::chain_object::{decode_exact, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// The fixed-width head of a peg-out: everything `peg::peg_out_confidential` decides on.
///
/// ⛔ EVERY FIELD IS BOUND INTO THE ATTESTED MESSAGE — `peg::peg_out_confidential_msg` covers the burned
/// note's nullifier, both new commitments and the redeem destination — so a peer re-tallying the quorum
/// is re-tallying over exactly these bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PegOutHeader {
    /// The burned USDm note's nullifier — the replay key that makes one note redeem once.
    pub usdm_nullifier: [u8; 32],
    /// The committed reserve AFTER the release leg (opaque digest).
    pub new_reserve_commit: crate::spend_frontier::Digest4,
    /// The committed circulating supply AFTER the burn leg (opaque digest).
    pub new_minted_commit: crate::spend_frontier::Digest4,
    /// ⭐ The executor's proposal nonce — part of the v2 statement every attestation signs
    /// (`peg::peg_out_confidential_msg`), carried so every grafting node re-verifies the SAME
    /// statement the custodians signed (the peg-in's `PegInHeader::proposal_nonce`, one lane over).
    pub proposal_nonce: [u8; 32],
    /// ⭐ THE BURN'S CROSS-BIND (§BB for the redeem, 2026-09-17). The burned note's `leaf_commit` —
    /// the value the executor and every attesting custodian verified the bond-validity carrier
    /// against — bound into the attested statement. (The node-side recomputation this doc once named,
    /// `chain_object::carried_burn_binds` over `spend_cross_bind(cm, nf)`, does not exist: `spend_cross_bind` was deleted
    /// by DB-363 because it linked a spend to its receive, `spend_frontier.rs:1845`; the commitment is hiding.) From the
    /// network upgrade it is this burn's `Leg` cross-bind, which the spender's absence wrapper is checked against
    /// (`chain_object::object_tag_roles`, A-F114). Before DB-363, without it the ledger released on
    /// every node while the note stayed in the unspent tree of every node that had not pooled the
    /// transaction (measured in-process: C's unspent root diverged from A's after the burn block).
    /// Bound into the attested statement, so an executor cannot swap it after gathering.
    pub leaf_commit: crate::spend_frontier::Digest4,
    /// ⭐ DB-273 §19.3 L2 — `oli::owner_clue_digest(clue)` of the CHANGE note's OLI clue, bound into the v4 statement
    /// the quorum signs (`peg::peg_out_confidential_msg`), so a relay that strips or replaces the carried clue voids
    /// the object, where before the remainder settled unfiled for its owner. All-zero exactly when no change note rides.
    pub change_owner: [u8; 32],
    /// ⛔⛔⛔ DB-365 — the change note's COMMITMENT, `leaf_to_cm_bytes(out1_cm)`: the out1 the burn carrier binds with
    /// conservation (burn + change = the burned note's value) and every attesting custodian verified it against, signed
    /// in the v5 statement. [`decode`] refuses a carried change note whose commitment is not this value — the owner
    /// clue alone did not bind WHICH note, so a relay re-framed an honest object with a note of its own (MEASURED
    /// 2026-09-30: a 10⁹-unit note justified on a peer fed only the block). Always the signed out1, even when no change
    /// note rides (then it is credited nowhere).
    pub change_cm: [u8; 32],
}

/// The EXACT payload type: header, the redeem-floor solvency carrier, the COMMITMENT to the foreign redeem
/// destination, the attestations as raw `(pubkey, sig)` pairs, and the redeemer's change note.
///
/// ⭐ DB-110 (2026-09-19): the third column used to be the destination ADDRESS in cleartext, and its WIDTH
/// alone named the foreign chain. It is now a fixed 32-byte commitment — one width for every redeem, on
/// every chain, so the object leaks neither the address nor its length.
pub type PegOutPayload = (
    PegOutHeader,
    Vec<u8>,
    [u8; 32],
    Vec<(Vec<u8>, Vec<u8>)>,
    Vec<u8>,
    Vec<([u8; 32], Vec<u8>)>, // O1-FOOTPRINT-REVIEWED: the sealed per-custodian legs, bounded by PEG_ATTEST_SEALED_MAX (decode refuses wider) — the block CARRIES what every custodian needs to apply it (DB-58)
    Vec<u8>, // DB-273 §19.3 L2: the change note's owner clue — O1-FOOTPRINT-REVIEWED: bounded by peg_in_tx::OWNER_CLUE_MAX (decode refuses wider)
    TicketParts, // §BR-5: the cash-out ticket, its leg envelopes and its epoch ciphertext — O1-FOOTPRINT-REVIEWED: bounded in `decode`
);

/// ⭐ §BR-5 / §BR-9a step (c) — THE CASH-OUT TICKET'S PARTS a peg-out carries: the constant-width ticket (`cashout_ticket`),
/// the requester's sealed leg envelopes (one per custodian: the destination kind, the leg blind, the change clue, the
/// pay-after — no key share), and the ONE epoch ciphertext encapsulating the ticket key to the final key of the piece's epoch
/// (`epoch_release::seal_ticket`). The ticket and the ciphertext's hash are bound into the signed `redeem_commit`
/// (`cashout_ticket::ticketed_commit`), so a relay that swaps either voids the payout. The destination is readable only once
/// two thirds of custody release the epoch at its batch (`epoch_release::open_epoch`).
pub type TicketParts = (Vec<u8>, Vec<([u8; 32], Vec<u8>)>, Vec<u8>);

/// The ticket parts' bounds: the ticket exactly `TICKET_BYTES`, one to `PEG_ATTEST_SEALED_MAX` envelopes of the request
/// envelope's width, the ciphertext exactly `epoch_key::CT_BYTES`.
#[must_use]
pub fn ticket_parts_well_formed(t: &TicketParts) -> bool {
    t.0.len() == crate::cashout_ticket::TICKET_BYTES
        && !t.1.is_empty()
        && t.1.len() <= crate::peg_attest::PEG_ATTEST_SEALED_MAX
        && t.1.iter().all(|(_, b)| b.len() == crate::peg_attest::request_sealed_len())
        && t.2.len() == crate::epoch_key::CT_BYTES
}

/// ⭐ THE REDEEM COMMITMENT THE QUORUM SIGNS (v6, lane funds-brb26 2026-11-01): the ticketed commitment bound to the exact
/// ticket bytes and epoch ciphertext the object carries. `redeem_commit` binds both only for whoever can OPEN it, and no
/// node can at the fold — so before v6 an executor (or a proposer before signatures) could carry an honest burn with swapped
/// ticket parts: the burn applied and the ticket never opened (the user's USDm destroyed, never paid). Every signer and
/// every door now signs/verifies this value, so a swapped part voids the quorum's signatures.
///
/// ⛔⭐ v7 (F-LEG, 2026-11-10) — AND TO THE SEALED LEGS. The per-custodian legs carry the RELEASE AMOUNT, each is a KEM
/// envelope to a PUBLIC key, and v6 left them outside what the quorum signs. MEASURED (pin
/// `a_two_of_two_custody_quorum_gathers_peg_out_attestations…`, the F-LEG arm): an honest, fully signed peg-out re-framed
/// with one custodian's leg re-sealed for 1000× the release was taken — that custodian booked 10,000,000 sats against a
/// release of 10,000. Whoever lays the object in a block could re-seal every leg, and every custodian would book and
/// co-sign the inflated amount to the burner's own bound destination: the reserve, for one small burn and one block.
/// The same class as the clue (v4), the change commitment (v5) and the ticket (v6): an object field outside the statement.
/// Every signer holds the full envelope list when it signs (`PegOutProposal::sealed`, which the executor publishes
/// unchanged), verifies ITS OWN leg against the carrier before it signs, and now signs the digest of all of them in
/// their order — so the legs a block carries are the legs the quorum signed, or its signatures do not verify.
/// A leg of a custodian that did not sign was checked by nobody; it is bound to what was proposed all the same, and a
/// wrong one books an amount the signing two thirds will not co-sign.
/// BORROWED: Bitcoin's SIGHASH_ALL — a signature commits to every output of the transaction it authorizes, so no relay
/// can change where the value goes after it is signed.
/// The ticket's own per-custodian envelopes (`TicketParts.1`) are bound by the same digest (dcash, on the bus, 2026-11-10):
/// they are read only at signing today, and they are the same class — a per-custodian list an object carries.
/// cons: none on the wire or in a block (a statement is hashed, never carried); 32 more bytes hashed per envelope.
#[must_use]
pub fn signed_redeem_commit(
    redeem_commit: &[u8; 32],
    ticket: &[u8],
    ticket_envelopes: &[([u8; 32], Vec<u8>)],
    epoch_ct: &[u8],
    sealed: &[([u8; 32], Vec<u8>)],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/peg-out/signed-redeem/v2");
    h.update(redeem_commit);
    h.update(&(ticket.len() as u64).to_le_bytes());
    h.update(ticket);
    h.update(&(epoch_ct.len() as u64).to_le_bytes());
    h.update(epoch_ct);
    for list in [ticket_envelopes, sealed] {
        h.update(&(list.len() as u64).to_le_bytes());
        for (id, blob) in list {
            h.update(id);
            h.update(&(blob.len() as u64).to_le_bytes());
            h.update(blob);
        }
    }
    *h.finalize().as_bytes()
}

/// ⭐ OWED, THE HAND-OVER (2026-11-11) — THE PARTS OF AN APPLIED CASH-OUT THAT BIND A CUSTODIAN'S LEG TO ITS BURN. A
/// custodian that adopted past a burn re-opens its leg from the block when its body window still holds it
/// (`Node::recover_peg_out_leg`, lane owed). When the block has left every body window nothing on the chain carries
/// the leg any more — and a payout needs two thirds of the vault to hold theirs. So every custodian that booked a
/// cash-out keeps THIS beside it until the release is paid, and hands it to a vault mate that asks
/// (`btc_payout::LegShare`): the statement's public fields, the quorum's signatures and the sealed parts exactly as
/// the object carried them. Everything here was public on the chain; the legs stay sealed to their custodians.
/// What it is NOT: the object's proofs (the reduction and burn carriers decided whether the burn APPLIED, which the
/// asker's own certified ledger already says) or its change note.
/// SAFE AT SCALE: the signatures and envelopes of the burn's own vault — eleven and sixteen once the cut is live
/// (about 80 KB), the bonded set's on a one-vault chain — per burn IN FLIGHT; an entry leaves when its release is
/// paid, so nothing here grows with height.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegProof {
    /// The ledger the burn paid from (`PegOutProofs::coin`): it names the vault whose signatures carry the object.
    pub coin: u32,
    pub new_reserve_commit: crate::spend_frontier::Digest4,
    pub new_minted_commit: crate::spend_frontier::Digest4,
    pub redeem_commit: [u8; 32],
    pub proposal_nonce: [u8; 32],
    pub leaf_commit: crate::spend_frontier::Digest4,
    pub change_owner: [u8; 32],
    pub change_cm: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by `MAX_CREDIT_ATTESTORS` pairs of `PEG_ATTEST_PUBKEY_MAX` / `PEG_ATTEST_SIG_MAX` bytes (`decode` refuses wider).
    pub attestors: Vec<(Vec<u8>, Vec<u8>)>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `PEG_ATTEST_SEALED_MAX` envelopes of exactly `peg_attest::sealed_len()` bytes (`decode` refuses any other).
    pub sealed: Vec<([u8; 32], Vec<u8>)>,
    /// The ticket, its share envelopes and its epoch ciphertext (`TicketParts`), bounded by `ticket_parts_well_formed`.
    pub ticket: TicketParts,
}

impl LegProof {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    /// One canonical, bounded reading: the bounds the cash-out object's own decode holds its parts to.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let p: Self = decode_exact(bytes)?;
        let ok = ticket_parts_well_formed(&p.ticket)
            && !p.attestors.is_empty()
            && p.attestors.len() <= crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS
            && p.attestors.iter().all(|(pk, sig)| pk.len() <= crate::peg_attest::PEG_ATTEST_PUBKEY_MAX && sig.len() <= crate::peg_attest::PEG_ATTEST_SIG_MAX)
            && p.sealed.len() <= crate::peg_attest::PEG_ATTEST_SEALED_MAX
            && p.sealed.iter().all(|(_, b)| b.len() == crate::peg_attest::sealed_len())
            && p.redeem_commit != [0u8; 32];
        ok.then_some(p)
    }
    /// The signatures as the ledger's tally reads them.
    #[must_use]
    pub fn mint_attestors(&self) -> Vec<MintAttestor> {
        self.attestors.iter().map(|(pubkey, sig)| MintAttestor { pubkey: pubkey.clone(), sig: sig.clone() }).collect()
    }
}

/// Test builds: well-formed ticket parts that open nothing (for codec and door pins that do not exercise the release).
#[cfg(test)]
#[must_use]
pub fn ticket_parts_for_test() -> TicketParts {
    (
        vec![0x7Au8; crate::cashout_ticket::TICKET_BYTES],
        vec![([0x7Bu8; 32], vec![0u8; crate::peg_attest::request_sealed_len()])],
        vec![0x7Cu8; crate::epoch_key::CT_BYTES],
    )
}

/// ⭐⭐ B15 (lane funds 2026-10-29) — THE PROOFS A PEG-OUT CARRIES, in its one proof column: the burn-bound solvency carrier,
/// the burn commitment both proofs open, the burned output's commitment, the committed burn carrier and the burned note's
/// one-step membership. Every node then verifies at the fold that the supply falls by exactly what the burned note destroyed —
/// before, the burn amount reached the solvency carrier on the custodians' signature alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegOutProofs {
    /// O1-FOOTPRINT-REVIEWED: bounded by `SolvencyProof::MAX_PROOF_BYTES` in `decode`.
    pub solvency: Vec<u8>,
    pub burn_commit: crate::spend_frontier::Digest4,
    /// ⭐ §18.14 — the coin ledger a coin note's burn pays from; 0 for USDm's cash-out
    pub coin: u32,
    /// The burned output's commitment (`cashout_ticket::burn_out_cm`), canonical bytes.
    pub out0_cm: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded in `decode`.
    pub burn: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded in `decode`.
    pub membership: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded in `decode`.
    pub tip: Vec<u8>,
}

impl PegOutProofs {
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    /// One canonical, bounded proof bundle.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let p: Self = decode_exact(bytes)?;
        let max = crate::solvency::SolvencyProof::MAX_PROOF_BYTES;
        let ok = [&p.solvency, &p.burn, &p.membership].iter().all(|c| !c.is_empty() && c.len() <= max) && p.tip.len() <= max;
        ok.then_some(p)
    }
    /// ⭐ THE STATELESS HALF: the committed burn destroys, into `out0_cm`, exactly the amount `burn_commit` hides, from the note
    /// `leaf_commit` names under nullifier `nf`, with the signed change `change_cm` as out1 and the protocol's fee.
    #[must_use]
    pub fn burn_verifies(&self, nf: &[u8; 32], leaf_commit: crate::spend_frontier::Digest4, change_cm: &[u8; 32]) -> bool {
        let (Some(nfd), Some(o0), Some(o1)) = (
            crate::spend_frontier::cm_bytes_to_root(nf),
            crate::spend_frontier::cm_bytes_to_root(&self.out0_cm),
            crate::spend_frontier::cm_bytes_to_root(change_cm),
        ) else {
            return false;
        };
        burn_carrier_verifies(self.coin, &self.burn, o0, o1, nfd, leaf_commit, self.burn_commit)
    }
}

/// ⭐ THE ONE READ OF A BURN'S CARRIER, for USDm (`coin` 0) and for a coin note (§18.14): the burned note's asset is what the carrier proves, so a note of one asset can never pay as another's.
#[must_use]
pub fn burn_carrier_verifies(
    coin: u32,
    carrier: &[u8],
    out0: crate::spend_frontier::Digest4,
    out1: crate::spend_frontier::Digest4,
    nf: crate::spend_frontier::Digest4,
    leaf_commit: crate::spend_frontier::Digest4,
    burn_commit: crate::spend_frontier::Digest4,
) -> bool {
    // SAFE AT SCALE: `coin` is the LEDGER the burn pays from — a vault's own ledger above vault 0 (`peg::vault_ledger`).
    // The NOTE burned is the asset's: USDm and each coin are one asset on the chain, whatever vault pays them out.
    let Some(asset) = crate::peg::ledger_asset_checked(coin) else { return false };
    if asset == 0 {
        return usdm_decider::whir_rec_block::verify_burn_validity_committed_bytes(carrier, out0, out1, nf, leaf_commit, burn_commit, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC);
    }
    crate::peg::PegLedger::is_coin_ledger(asset)
        && usdm_decider::whir_rec_block::verify_asset_burn_committed_bytes(carrier, out0, out1, nf, leaf_commit, burn_commit, usdm_decider::whir_rec_block::wrapped_asset_tag_u32(asset))
}

/// The change owner a peg-out names: the canonical digest of the change note's clue, or all-zero when the object
/// carries no change note (and therefore no clue). ONE rule, used by the publisher and re-checked by `decode`.
#[must_use]
pub fn change_owner_of(owner_clue: &[u8]) -> [u8; 32] {
    if owner_clue.is_empty() {
        [0u8; 32]
    } else {
        crate::oli::owner_clue_digest(owner_clue)
    }
}

/// The canonical payload bytes (unframed). Fail-closed: an encode failure yields EMPTY bytes, which do not
/// `unframe` into a decodable object, so every door refuses them on this object alone.
#[must_use]
pub fn encode(
    header: &PegOutHeader,
    carrier: &[u8],
    redeem_commit: &[u8; 32],
    attestors: &[MintAttestor],
    change_note: &[u8],
    sealed: &[([u8; 32], Vec<u8>)],
    owner_clue: &[u8],
    ticket: &TicketParts,
) -> Vec<u8> {
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = attestors
        .iter()
        .map(|a| (a.pubkey.clone(), a.sig.clone()))
        .collect();
    postcard::to_stdvec(&(
        header,
        carrier.to_vec(),
        // DB-110: 32 RAW bytes, not a length-prefixed Vec — `PegOutPayload`'s third column is `[u8; 32]`,
        // and ONE consensus object has ONE encoding. Encoding it as a Vec made every honest peg-out
        // undecodable, so `wrapper_binds_object` refused it at the publisher's own pool door.
        *redeem_commit,
        pairs,
        change_note.to_vec(),
        sealed.to_vec(),
        owner_clue.to_vec(),
        ticket.clone(),
    ))
    .unwrap_or_default()
}

/// The FRAMED blob — the one form this object travels in.
#[must_use]
pub fn wire(
    header: &PegOutHeader,
    carrier: &[u8],
    redeem_commit: &[u8; 32],
    attestors: &[MintAttestor],
    change_note: &[u8],
    sealed: &[([u8; 32], Vec<u8>)],
    owner_clue: &[u8],
    ticket: &TicketParts,
) -> Vec<u8> {
    crate::chain_object::frame(
        Class::PegOut,
        &encode(header, carrier, redeem_commit, attestors, change_note, sealed, owner_clue, ticket),
    )
}

/// A decoded peg-out: header, carrier, redeem commitment, attestors, change note, sealed legs, change owner clue, ticket parts.
pub type PegOutDecoded =
    (PegOutHeader, Vec<u8>, [u8; 32], Vec<MintAttestor>, Vec<u8>, Vec<([u8; 32], Vec<u8>)>, Vec<u8>, TicketParts);

// CHAIN-PUBLISH-REVIEWED: a wire-field parser (bytes → typed object), a read of the request; it moves
// nothing — the signature is `fn(&[u8]) -> Option<..>` with no `&mut Node` to mutate.
/// Refuses rather than guesses. Strict full-consumption decode, so `encode(a) || junk` is not a second,
/// differently-identified copy of one peg-out.
///
/// ⭐⭐⭐ THE BOUNDS LIVE HERE: an unattested peg-out, one with no carrier, or one naming no redeem
/// destination is not an object at all. The attestor ceiling is `bridge_credit_tx::MAX_CREDIT_ATTESTORS`
/// (= `params::DAG_WIDTH_CEILING`), a fixed protocol constant, so a decoded peg-out's footprint carries no
/// term in height, supply or peer count.
/// ⭐ DB-273 §19.3 L2 — the CHANGE OWNER: a change note rides with exactly one non-empty clue whose canonical digest is
/// the header's `change_owner` (which the quorum signed); no change note rides with no clue and a zero `change_owner`.
/// Anything else — a stripped, replaced or oversized clue, or a clue with nothing to own — is not an object, so one
/// peg-out has one encoding and its remainder is never settled unfiled for its owner.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<PegOutDecoded> {
    let (h, carrier, redeem_commit, pairs, change_note, sealed, owner_clue, ticket) = decode_exact::<PegOutPayload>(payload)?;
    if !ticket_parts_well_formed(&ticket) {
        return None; // §BR-5: a cash-out without its whole ticket is not a cash-out
    }
    if owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX
        || change_note.is_empty() != owner_clue.is_empty()
        || change_owner_of(&owner_clue) != h.change_owner
    {
        return None; // the change's owner is not the one the quorum signed
    }
    // ⛔⛔⛔ DB-365 — the change NOTE is the one the quorum signed: its commitment, read by the ONE injective reader every
    // credit door uses (`note_cm_of`), must be the v5 statement's `change_cm` (the burn carrier's out1). This is the only
    // place a peg-out's change is admitted, so the executor's pool door, every graft apply and the credit justifier
    // (`chain_object::carried_note_payloads`) all refuse a swapped note here.
    if !change_note.is_empty()
        && crate::spend_frontier::note_cm_of(&change_note).map(crate::spend_frontier::leaf_to_cm_bytes) != Some(h.change_cm)
    {
        return None; // a change note the quorum never signed for
    }
    if sealed.len() > crate::peg_attest::PEG_ATTEST_SEALED_MAX {
        return None; // more envelopes than the bonded custodian set can hold
    }
    if carrier.is_empty() {
        return None; // a peg-out with no reduction proof releases nothing
    }
    if redeem_commit == [0u8; 32] {
        return None; // a redeem committing to nothing is not a redeem
    }
    if pairs.is_empty() {
        return None; // unattested is not a peg-out
    }
    if pairs.len() > crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS {
        return None; // more signatures than the bonded set can hold
    }
    let attestors: Vec<MintAttestor> = pairs
        .into_iter()
        .map(|(pubkey, sig)| MintAttestor { pubkey, sig })
        .collect();
    Some((h, carrier, redeem_commit, attestors, change_note, sealed, owner_clue, ticket))
}

/// What applying a peg-out object did.
#[derive(PartialEq, Eq, Debug)]
pub enum PegOutApply {
    /// Not a peg-out object — left entirely alone.
    NotPegOut,
    /// The burn retired and the reserve reduction advanced on THIS node, from the object's own bytes.
    Redeemed,
    /// Refused before anything moved, with the peg's own verdict.
    Refused(crate::peg::PegOutcome),
}

// CHAIN-PUBLISH-REVIEWED: the apply half, driven by the PegOut chain object at graft — every node runs it
// on the bytes a block carries, and the publish half is `Node::execute_peg_out_burn_verified`.


#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// ⭐ DB-273 §19.3 L2 — ONE ENCODING FOR THE CHANGE'S OWNER: a change note rides with exactly the clue the signed
    /// `change_owner` names, and no change note rides with no clue and a zero owner. Every other shape — a stripped,
    /// replaced or oversized clue, a clue with no note to own, a zero owner beside a note — is not an object.
    /// CALIBRATION: both honest shapes decode, and the object's staged record is its own change and clue.
    #[test]
    fn a_peg_outs_change_owner_has_one_encoding_and_a_forged_clue_is_not_an_object() {
        let clue = vec![0xC7u8; crate::peg_in_tx::OWNER_CLUE_MAX];
        // A note in its carriage form (`cm ‖ slot`) over a canonical commitment — the out1 the quorum signed.
        let note_of = |lanes: [u64; 4]| {
            let mut n = crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&lanes)).to_vec();
            n.resize(crate::chain_object::NOTE_REF_BYTES, 0x5C);
            n
        };
        let note = note_of([21, 22, 23, 24]);
        let signed_cm: [u8; 32] = note[..32].try_into().expect("32 bytes");
        let hdr = |owner: [u8; 32]| PegOutHeader {
            usdm_nullifier: [1u8; 32],
            new_reserve_commit: usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            new_minted_commit: usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
            proposal_nonce: [2u8; 32],
            leaf_commit: usdm_decider::poseidon2_compress::lanes_of(&[9, 10, 11, 12]),
            change_owner: owner,
            change_cm: signed_cm,
        };
        let a = vec![MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }];
        let tp = ticket_parts_for_test();
        let enc = |h: &PegOutHeader, change: &[u8], c: &[u8]| encode(h, &[3u8; 16], &[4u8; 32], &a, change, &[], c, &tp);
        let owned = hdr(change_owner_of(&clue));
        let honest = decode(&enc(&owned, &note, &clue)).expect("CALIBRATION: the honest change owner decodes");
        assert_eq!(honest.6, clue, "CALIBRATION: the decoded object carries its change's clue");
        assert!(decode(&enc(&hdr([0u8; 32]), &[], &[])).is_some(), "CALIBRATION: no change, no clue, zero owner decodes");
        assert!(decode(&enc(&owned, &note, &[])).is_none(), "⛔ a STRIPPED change clue decoded");
        assert!(decode(&enc(&owned, &note, &[0xD8u8; 608])).is_none(), "⛔ a REPLACED change clue decoded");
        let long = vec![0xC7u8; crate::peg_in_tx::OWNER_CLUE_MAX + 1];
        assert!(decode(&enc(&hdr(change_owner_of(&long)), &note, &long)).is_none(), "⛔ an oversized clue decoded");
        assert!(decode(&enc(&hdr([0u8; 32]), &note, &[])).is_none(), "⛔ a change note with a zero owner decoded");
        assert!(decode(&enc(&owned, &[], &clue)).is_none(), "⛔ a clue with no change note to own decoded");
        // ⛔⛔⛔ DB-365 — the change NOTE is the signed one: a note of any other commitment under the same header, owner
        // and clue is not an object; nor is a note whose front is not a canonical commitment at all.
        assert!(
            decode(&enc(&owned, &note_of([31, 32, 33, 34]), &clue)).is_none(),
            "⛔⛔⛔ DB-365: a change note the quorum never signed for decoded"
        );
        assert!(decode(&enc(&owned, &vec![0xFFu8; 64], &clue)).is_none(), "⛔ a non-canonical change commitment decoded");
        let blob = wire(&owned, &[3u8; 16], &[4u8; 32], &a, &note, &[], &clue, &tp);
        let mut short = tp.clone();
        short.2.clear();
        assert!(decode(&encode(&owned, &[3u8; 16], &[4u8; 32], &a, &note, &[], &clue, &short)).is_none(), "⛔ §BR-5: a peg-out without its share commitments decoded");
        let mut wide = tp.clone();
        wide.0.push(0);
        assert!(decode(&encode(&owned, &[3u8; 16], &[4u8; 32], &a, &note, &[], &clue, &wide)).is_none(), "⛔ §BR-5: a ticket of another width decoded");
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&note[..32]);
        assert_eq!(
            crate::chain_object::object_owner_clue_records(&blob),
            Some(vec![(cm, clue)]),
            "the staged record is the object's own change and clue"
        );
    }
}
