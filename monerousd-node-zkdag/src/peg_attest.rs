// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐⭐ THE PEG-IN ATTESTATION LANE — how a t-of-n custody quorum authorizes ONE confidential mint.
//!
//! A confidential peg-in mints only under `peg::threshold_ok`: ≥2/3 of the BONDED weight must sign
//! `peg_in_confidential_msg(deposit_id, new_reserve_commit, new_minted_commit, recipient, nonce)`. Until
//! 2026-09-17 the only attestation a node could ever hold was ITS OWN (`execute_peg_in` signs with the
//! local bridge signer and appends whatever `attestors_hex` the RPC caller pasted). That is a 1-of-1
//! quorum wearing a threshold's clothes: the moment the chain seated a SECOND validator — the genesis
//! quorum the owner asked for, "the first two nodes on the chain to bond and create the quorum" — the
//! first real-node mint answered `INSUFFICIENT_THRESHOLD`, and nothing anywhere could gather the peer's
//! signature. The wallet's `gather_peg_attestations` had zero callers and aimed at a `/attest_peg_in`
//! route that did not exist; and node RPC is loopback-only by design, so no client can reach a peer's
//! signer at all. The attestation has to travel the way every other validator statement travels: as a
//! gossip message every node relays, the finality-vote shape (`WireMsg::Vote`).
//!
//! ## Why the delta is SEALED, not carried
//!
//! An attestor cannot sign what it cannot check. The commitments in the statement are a function of the
//! custodian OPENING (reserve total + blind, minted total + blind) and the transition `(deposit, mint)`;
//! `peg::PegLedger::next_op_blind` chains the blinds deterministically from the opening, the amounts and the delta's
//! SEALED blind (so no observer can re-derive the chain from the public genesis blinds), so every custodian holding the
//! same opening and told the same sealed delta derives the SAME `(new_reserve_commit, new_minted_commit)` — and
//! an executor that proved a larger hidden deposit than it told the quorum produces commits nobody else
//! reproduces, so its threshold fails. That check needs the delta on every custodian. It must NOT reach
//! anyone else: #75's design invariant is "custodian threshold knowing the totals is FINE (they hold the
//! reserve); the win is GENERIC NODES + observers can't compute them". So the proposal carries the delta
//! ML-KEM-768-sealed to EACH bonded custodian's registered encapsulation key (`MembershipBondHeader::kem_ek`),
//! the same seal shape `account_da::seal_entry_to` uses; a relaying node sees two opaque commitments and
//! ciphertexts. DIGITAL-CASH-PRIVACY-REVIEWED: no amount, address or value crosses the wire in the clear —
//! the plaintext lives only inside a per-custodian KEM envelope; the body is CONSTANT-size so its length
//! reveals nothing either.
//!
//! ## The lane
//!
//! 1. `/peg_in_execute` on the EXECUTOR: own opening → `orchestrate_peg_in` → the proposed commits; seal
//!    the delta to every bonded custodian; broadcast [`PegInProposal`] as `WireMsg::PegAttestReq`.
//! 2. Every bonded custodian that receives it (`node_runtime`): open its own envelope, verify from ITS
//!    OWN opening + ITS OWN foreign-chain watcher, sign, broadcast [`PegInAttestation`] as
//!    `WireMsg::PegAttestResp`. Relays re-gossip a fresh valid one exactly like a vote.
//! 3. The executor's next `/peg_in_execute` poll finds the gathered signatures in its bounded pending
//!    store, `execute_peg_in` passes threshold, the `Class::PegIn` object publishes, the note mints.
//! 4. When the block carrying that object grafts, a custodian holding the delta advances ITS opening
//!    (`Node::advance_custodian_opening_from_delta`), so it can attest the NEXT mint — the openings stay
//!    in lockstep with the commitments on every custodian, from the same chain order.
//!
//! Borrowed shape, cited: THORChain's TSS-signed outbound is a p2p gathering among bonded nodes, never a
//! client fanning out to node RPCs; a Bitcoin multisig spend gathers signatures over ONE statement.

use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// A foreign reserve address never exceeds this (bech32m ≤ 90; a Monero address is 95). The sealed body is
/// padded to it so every envelope is the same length whatever the address.
pub const PEG_ATTEST_ADDRESS_MAX: usize = 128;
/// Custodian envelopes per proposal — one per bonded custodian with a registered `kem_ek`. A t-of-n custody
/// quorum wider than this is not a realistic custodian set (THORChain caps its active set near 100).
pub const PEG_ATTEST_SEALED_MAX: usize = 256;
/// Proposals a node tracks at once (each with at most `PEG_ATTEST_SEALED_MAX` attestations). Oldest-first
/// eviction; a proposal is dropped the moment its deposit mints or is refused.
pub const PEG_ATTEST_PENDING_MAX: usize = 64;
/// DB-5: how many of this custodian's recent openings it keeps, keyed by the commitments each opens,
/// so a jump that abandons its own block can rewind. O1: a fixed ring.
pub const CUSTODY_OPENING_HISTORY_MAX: usize = 16;
/// DB-5: how many attested-but-unapplied deltas the resync permutes to reach the certified commitments.
pub const RESYNC_REPLAY_MAX: usize = 5;
/// §DD interim: how many (one-time id, block) pairs a node remembers so an adopt can forget the ids of
/// blocks the certified chain abandoned. O1: a fixed ring.
pub const APPLIED_ONE_TIME_ID_RING_MAX: usize = 512;
/// The executor re-broadcasts a still-unsatisfied proposal no more often than this.
pub const PEG_ATTEST_REBROADCAST_MS: u64 = 10_000;
/// Authentication tag on a sealed envelope (blake3-keyed over the shared secret + body).
pub const PEG_ATTEST_TAG_BYTES: usize = 8;
/// The CONSTANT sealed body: `deposit_value(16 LE) ‖ mint(16 LE) ‖ addr_len(1) ‖ addr(PEG_ATTEST_ADDRESS_MAX)`.
/// DB-80: + 32 bytes for the mint-delta commitment blind (`d_blind`) every custodian needs to open
/// `PegInProposal::delta_commit` — the amount itself never rides in the clear.
/// §BR-1 (2026-10-28): + 8 bytes for `pay_after`, the earliest chain height a peg-out piece may be paid at (the sealed
/// privacy delay); zero on a peg-in leg.
/// §BR-2 (2026-10-28): + `SWEEP_AUTH_BYTES` for the co-signed deposit's sweep authorization (zero-filled when absent).
pub const PEG_ATTEST_BODY_BYTES: usize =
    16 + 16 + 1 + PEG_ATTEST_ADDRESS_MAX + crate::spend_frontier::DIGEST_LANE_BYTES + 8 + SWEEP_AUTH_BYTES;
/// ML-DSA-65 encoded key / signature ceilings (1952 / 3309 bytes) — a decode refuses anything wider.
pub const PEG_ATTEST_PUBKEY_MAX: usize = 4096;
pub const PEG_ATTEST_SIG_MAX: usize = 8192;

/// ⭐ §BR-2 (spec §14) — THE CO-SIGNED DEPOSIT'S SWEEP AUTHORIZATION, sealed to every custodian beside the mint it lets
/// them complete: the depositor's x-only key `D` (the deposit output's `sweep` and `refund` leaves name it), the deposit
/// coin, the fee the sweep pays, and the depositor's BIP-340 signature over the sweep transaction
/// (`btc_tx::deposit_sweep_payout`). A custodian attests a Bitcoin mint only when this verifies over that exact
/// transaction, so after any mint the custody can sweep with no wallet online — and a wallet can never mint and then
/// take the deposit back through the refund leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SweepAuth {
    pub depositor_x: [u8; 32],
    /// The deposit coin, txid in internal byte order.
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sats: u64,
    pub fee_sats: u64,
    pub sig: [u8; 64],
}

/// The encoded width: a presence flag, then D ‖ txid ‖ vout ‖ value ‖ fee ‖ sig (zero-filled when absent, so every
/// envelope keeps one length).
pub const SWEEP_AUTH_BYTES: usize = 1 + 32 + 32 + 4 + 8 + 8 + 64;

impl SweepAuth {
    fn encode_opt(a: Option<&SweepAuth>, out: &mut Vec<u8>) {
        match a {
            None => out.extend_from_slice(&[0u8; SWEEP_AUTH_BYTES]),
            Some(a) => {
                out.push(1);
                out.extend_from_slice(&a.depositor_x);
                out.extend_from_slice(&a.txid);
                out.extend_from_slice(&a.vout.to_le_bytes());
                out.extend_from_slice(&a.value_sats.to_le_bytes());
                out.extend_from_slice(&a.fee_sats.to_le_bytes());
                out.extend_from_slice(&a.sig);
            }
        }
    }
    /// `Some(None)` = absent; `None` = malformed (a flag that is neither 0 nor 1, or a short body).
    fn decode_opt(b: &[u8]) -> Option<Option<SweepAuth>> {
        if b.len() < SWEEP_AUTH_BYTES {
            return None;
        }
        match b[0] {
            0 => Some(None),
            1 => Some(Some(SweepAuth {
                depositor_x: b[1..33].try_into().ok()?,
                txid: b[33..65].try_into().ok()?,
                vout: u32::from_le_bytes(b[65..69].try_into().ok()?),
                value_sats: u64::from_le_bytes(b[69..77].try_into().ok()?),
                fee_sats: u64::from_le_bytes(b[77..85].try_into().ok()?),
                sig: b[85..149].try_into().ok()?,
            })),
            _ => None,
        }
    }
}

/// What only the custodians learn: the transition this proposal asks them to attest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PegInDelta {
    pub deposit_value: u128,
    pub mint: u128,
    pub reserve_address: String,
    /// DB-80: the blind of `delta_commit = solvency_commit_256(mint, d_blind)`; chosen by the depositor's
    /// wallet (it proves the mint-validity carrier with it), sealed to every custodian. Eight field lanes.
    pub d_blind: Digest4,
    /// §BR-1: on a peg-out leg, the earliest chain height the piece may be paid at — the privacy delay the wallet drew,
    /// bound into `peg::redeem_commit` so every custodian signs the same one and none pays early. Zero on a peg-in.
    pub pay_after: u64,
    /// §BR-2: on a Bitcoin mint, the depositor's sweep authorization (spec §14); `None` on every other leg.
    pub sweep: Option<SweepAuth>,
}

/// The executor's proposal, as relayed by every node. Two opaque commitments, the recipient, and one
/// sealed envelope per bonded custodian.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegInProposal {
    /// DB-77: which ledger this mint moves — 0 = the native USDm peg, otherwise a registered wrapped asset.
    /// ONE lane carries every custodial mint; the statement, the opening and the chain object branch on it.
    pub asset_id: u32,
    pub deposit_id: [u8; 32],
    pub recipient: [u8; 32],
    pub new_reserve_commit: Digest4,
    pub new_minted_commit: Digest4,
    /// DB-80: `solvency_commit_256(mint, d_blind)` — the ONE committed number both carriers open; the
    /// mint amount itself is nowhere on the wire or the chain. Part of the signed statement.
    pub delta_commit: Digest4,
    /// The executor's per-proposal nonce — part of the signed statement (`peg_in_confidential_msg` v2),
    /// carried on the `Class::PegIn` object, so a signature is valid for THIS proposal and no other.
    pub nonce: [u8; 32],
    /// `(custodian validator id, sealed delta)` — see [`seal_delta_to`]. Every envelope is exactly
    /// `sealed_len()` bytes; `decode` refuses any other shape before a key is touched.
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SEALED_MAX — by construction, `decode` returns `None`
    /// past that count and past `sealed_len()` per envelope, so no door ever reads a wider list.
    pub sealed: Vec<([u8; 32], Vec<u8>)>,
    /// DB-113: the same admission stamp [`PegRequest`] carries. A proposal makes every node on the mesh
    /// verify signatures and hold a gathering slot, so it has to cost the sender what a pooled transaction
    /// costs — otherwise proposals are free to mint and every node remembers them.
    pub stamp: u64,
    /// ⭐ §BR-4 B4-2 — on a unit open, the unit a custodian checks before signing (`UnitClaim::covered`); the signed deposit id
    /// is `UnitClaim::deposit_id`, so the statement binds it. `None` on every other mint.
    #[serde(default)]
    pub unit: Option<crate::unit_open_tx::UnitClaim>,
}

/// One custodian's signature over the proposal's statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegInAttestation {
    /// DB-77: names the slot (native or wrapped) this signature belongs to — see [`PegInProposal::slot_key`].
    pub asset_id: u32,
    pub deposit_id: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_PUBKEY_MAX bytes (enforced at decode)
    pub pubkey: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SIG_MAX bytes (enforced at decode)
    pub sig: Vec<u8>,
}

/// One deposit's gathering state on a node (`Node::peg_attest_pending`).
#[derive(Clone, Debug)]
pub struct PendingProposal {
    pub proposal: PegInProposal,
    /// The delta, when this node AUTHORED the proposal (executor) or opened its own envelope (custodian).
    pub delta: Option<PegInDelta>,
    /// True on the executor only: a relayed proposal for the same deposit never displaces an authored one.
    pub authored: bool,
    /// Verified, per-custodian-deduplicated signatures over `proposal.statement()`.
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SEALED_MAX (one per bonded custodian, dedup by key id)
    pub attestations: Vec<crate::psm::MintAttestor>,
    pub first_seen_ms: u64,
    pub last_broadcast_ms: u64,
}

/// The constant envelope length: KEM ciphertext ‖ tag ‖ body.
#[must_use]
pub fn sealed_len() -> usize {
    crate::pqkem::ciphertext_len() + PEG_ATTEST_TAG_BYTES + PEG_ATTEST_BODY_BYTES
}

fn stream_key(ss: &[u8]) -> [u8; 32] {
    let mut kh = blake3::Hasher::new();
    kh.update(b"MUSD/peg-attest/delta-key/v1");
    kh.update(ss);
    *kh.finalize().as_bytes()
}

fn keystream(key: &[u8; 32], ct: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"MUSD/peg-attest/stream/v1");
    h.update(ct); // nonce = the fresh KEM ciphertext itself: two seals of one delta never share bytes
    let mut out = vec![0u8; PEG_ATTEST_BODY_BYTES];
    h.finalize_xof().fill(&mut out);
    out
}

fn tag_of(ss: &[u8], body: &[u8]) -> [u8; PEG_ATTEST_TAG_BYTES] {
    let mut th = blake3::Hasher::new();
    th.update(b"MUSD/peg-attest/delta-tag/v1");
    th.update(ss);
    th.update(body);
    let mut t = [0u8; PEG_ATTEST_TAG_BYTES];
    t.copy_from_slice(&th.finalize().as_bytes()[..PEG_ATTEST_TAG_BYTES]);
    t
}

/// Seal the delta to ONE custodian's ML-KEM-768 encapsulation key: `ct ‖ tag ‖ body`, constant length.
/// `None` for a malformed key or an over-long address (fail-closed, never a truncated address).
pub fn seal_delta_to(custodian_ek: &[u8], d: &PegInDelta) -> Option<Vec<u8>> {
    let addr = d.reserve_address.as_bytes();
    if addr.len() > PEG_ATTEST_ADDRESS_MAX {
        return None;
    }
    let (ss, ct) = crate::pqkem::encapsulate(custodian_ek)?;
    let mut body = Vec::with_capacity(PEG_ATTEST_BODY_BYTES);
    body.extend_from_slice(&d.deposit_value.to_le_bytes());
    body.extend_from_slice(&d.mint.to_le_bytes());
    body.push(addr.len() as u8);
    body.extend_from_slice(addr);
    body.resize(16 + 16 + 1 + PEG_ATTEST_ADDRESS_MAX, 0);
    body.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&d.d_blind));
    body.extend_from_slice(&d.pay_after.to_le_bytes());
    SweepAuth::encode_opt(d.sweep.as_ref(), &mut body);
    body.resize(PEG_ATTEST_BODY_BYTES, 0);
    let ks = keystream(&stream_key(&ss), &ct);
    for (b, k) in body.iter_mut().zip(ks.iter()) {
        *b ^= k;
    }
    let tag = tag_of(&ss, &body);
    let mut out = Vec::with_capacity(sealed_len());
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&body);
    Some(out)
}

/// Open an envelope with this custodian's decapsulation key. `None` when it is not ours (ML-KEM implicit
/// rejection yields a different secret, so the tag separates "mine" from "not mine") or malformed.
pub fn open_delta(custodian_dk: &[u8], blob: &[u8]) -> Option<PegInDelta> {
    if blob.len() != sealed_len() {
        return None;
    }
    let ct_len = crate::pqkem::ciphertext_len();
    let ct = &blob[..ct_len];
    let tag = &blob[ct_len..ct_len + PEG_ATTEST_TAG_BYTES];
    let sealed_body = &blob[ct_len + PEG_ATTEST_TAG_BYTES..];
    let ss = crate::pqkem::decapsulate(ct, custodian_dk)?;
    if tag_of(&ss, sealed_body) != tag {
        return None;
    }
    let ks = keystream(&stream_key(&ss), ct);
    let body: Vec<u8> = sealed_body.iter().zip(ks.iter()).map(|(b, k)| b ^ k).collect();
    let mut dv = [0u8; 16];
    dv.copy_from_slice(&body[..16]);
    let mut mv = [0u8; 16];
    mv.copy_from_slice(&body[16..32]);
    let alen = body[32] as usize;
    if alen > PEG_ATTEST_ADDRESS_MAX {
        return None;
    }
    let reserve_address = String::from_utf8(body[33..33 + alen].to_vec()).ok()?;
    let boff = 16 + 16 + 1 + PEG_ATTEST_ADDRESS_MAX;
    let d_blind = crate::spend_frontier::digest_from_lane_bytes(&body[boff..boff + crate::spend_frontier::DIGEST_LANE_BYTES])?;
    let poff = boff + crate::spend_frontier::DIGEST_LANE_BYTES;
    let pay_after = u64::from_le_bytes(body[poff..poff + 8].try_into().ok()?);
    let sweep = SweepAuth::decode_opt(&body[poff + 8..])?;
    Some(PegInDelta {
        deposit_value: u128::from_le_bytes(dv),
        mint: u128::from_le_bytes(mv),
        reserve_address,
        d_blind,
        pay_after,
        sweep,
    })
}

impl PegInProposal {
    /// The statement every attestation signs — ONE spelling per ledger: `peg::peg_in_confidential_msg`
    /// for the native peg, `peg::wrapped_mint_confidential_msg` for a wrapped asset (DB-77).
    #[must_use]
    pub fn statement(&self) -> Vec<u8> {
        // SAFE AT SCALE: a bridge deposit's proposal names its proposer's vault's NATIVE ledger (`vault_ledger(vault, 0)`;
        // plain 0 on vault 0), and the PegIn door verifies the peg-in message whichever vault the object rides — so the
        // message is chosen by the ledger's ASSET, never by the raw id (MEASURED 2026-11-10: a vault-1 proposal was
        // signed under the wrapped-mint message and its six signatures failed the door's tally).
        // F-LEG (2026-11-11): the recipient a custodian signs is bound to every envelope this proposal carries, so the
        // object the executor frames must carry these exact legs, and a relay that re-seals one voids the signatures.
        let signed_recipient = crate::peg::peg_in_signed_recipient(&self.recipient, &self.sealed);
        if crate::peg::ledger_asset(self.asset_id) == crate::peg::NATIVE_PEG_ASSET_ID {
            crate::peg::peg_in_confidential_msg(
                &self.deposit_id,
                &self.new_reserve_commit,
                &self.new_minted_commit,
                &self.delta_commit,
                &signed_recipient,
                &self.nonce,
            )
        } else {
            crate::peg::wrapped_mint_confidential_msg(
                self.asset_id,
                &self.deposit_id,
                &self.new_reserve_commit,
                &self.new_minted_commit,
                &self.delta_commit,
                &signed_recipient,
            )
        }
    }
    /// The pending-map key: the deposit id itself for the native peg, the wrapped deposit key otherwise —
    /// so one BTC deposit id can back a native mint AND a wrapped mint of another asset without colliding.
    #[must_use]
    pub fn slot_key(&self) -> [u8; 32] {
        slot_key_for(self.asset_id, &self.deposit_id)
    }

    /// The commitments this proposal asks the quorum to sign — what a re-proposal is compared against.
    #[must_use]
    pub fn commits(&self) -> (Digest4, Digest4) {
        (self.new_reserve_commit, self.new_minted_commit)
    }

    /// This custodian's envelope, if the executor sealed one to it.
    #[must_use]
    pub fn envelope_for(&self, custodian_id: &[u8; 32]) -> Option<&[u8]> {
        self.sealed
            .iter()
            .find(|(id, _)| id == custodian_id)
            .map(|(_, b)| b.as_slice())
    }

    /// Wire bytes (postcard). Empty on an encode failure — which does not decode, so it is refused everywhere.
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Bounded decode: refuses more envelopes than `PEG_ATTEST_SEALED_MAX` and any envelope that is not the
    /// constant sealed length (fail-closed on shape, before any key is touched).
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let p: Self = crate::chain_object::decode_exact(bytes)?;
        if p.sealed.len() > PEG_ATTEST_SEALED_MAX {
            return None;
        }
        if p.sealed.iter().any(|(_, b)| b.len() != sealed_len()) {
            return None;
        }
        Some(p)
    }
}

/// ⭐ THE PEG-OUT DELTA — what a custodian must know to re-derive a redeem's commitments from its OWN
/// opening and to release the reserve: the reserve RELEASE, the USDm BURN and the redeem destination.
/// Sealed per custodian exactly as a peg-in delta is (#75: custodians may know totals, nobody else may).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PegOutDelta {
    pub release: u128,
    pub burn: u128,
    pub redeem_to: String,
    /// DB-110 (2026-09-19): the blind of `peg::redeem_commit(redeem_to, r_blind)` — the destination address
    /// rides ONLY here, sealed per custodian, and the chain carries the commitment. It travels in the sealed
    /// envelope's existing `d_blind` slot (the peg-out leg never used it), so the sealed wire is unchanged.
    pub r_blind: Digest4,
    /// §BR-1: the earliest chain height this piece may be paid at (the sealed privacy delay); see `PegInDelta::pay_after`.
    pub pay_after: u64,
}

/// The widest carrier a proposal may carry (the ≤1.8 MB proof pillar, with framing headroom); `decode`
/// refuses wider, so a relayed proposal is bounded by construction.
pub const PEG_ATTEST_CARRIER_MAX: usize = 2 * 1024 * 1024;
/// The widest membership endpoint (three digest lanes) a proposal may carry; `decode` refuses wider.
pub const PEG_ATTEST_TIP_MAX: usize = 1024;

/// ⭐ A PEG-OUT PROPOSAL — the executor's redeem, offered to the bonded custodians for attestation over the
/// gossip lane (the mirror of [`PegInProposal`]; 2026-09-17, §DB/item 3). Until this existed the redeem
/// quorum was whatever the CALLER pasted in `attestors_hex` (1-of-1 on the real quorum): a depositor's BTC
/// could enter custody and never come back once a second custodian was seated.
///
/// It carries, beside the two opaque commitments and the destination, the BURN EVIDENCE every custodian
/// re-verifies before it signs: the bond-validity carrier that proves the burned note's value equals the
/// sealed burn (bound to the nullifier and the note's leaf commitment), and the note-membership carrier
/// that binds that leaf to the chain this custodian holds. A custodian that signs a release it did not
/// verify would let one bonded executor drain the reserve against a small note — the amount is inside
/// the note, so no node but a custodian (who opens the sealed burn) can check it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegOutProposal {
    pub usdm_nullifier: [u8; 32],
    /// DB-110 (2026-09-19): `peg::redeem_commit(redeem_to, r_blind)` — the destination BITCOIN ADDRESS IS NOT
    /// CARRIED HERE. It used to be (`redeem_to: Vec<u8>`), publishing the edge "this burn pays address A" to
    /// every node and every chain observer while the Bitcoin side shows the reserve paying A — so a known
    /// peg-in linked straight to the exit. The address now rides ONLY the per-custodian sealed `PegOutDelta`,
    /// and each custodian re-derives this commitment from its own opening before it signs anything.
    pub redeem_commit: [u8; 32],
    pub new_reserve_commit: Digest4,
    pub new_minted_commit: Digest4,
    pub nonce: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SEALED_MAX envelopes of sealed_len() each (`decode` refuses wider)
    pub sealed: Vec<([u8; 32], Vec<u8>)>,
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_CARRIER_MAX (`decode` refuses wider)
    pub burn_carrier: Vec<u8>,
    pub out0_cm: Digest4,
    pub out1_cm: Digest4,
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_CARRIER_MAX (`decode` refuses wider)
    pub membership_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_TIP_MAX — by construction, `decode` returns `None`
    /// past it, so no door reads a wider tip.
    pub membership_tip: Vec<u8>,
    pub leaf_commit: Digest4,
    /// ⭐ DB-273 §19.3 L2 — the change note's owner digest (`peg_out_tx::change_owner_of`), signed in the v4 statement.
    pub change_owner: [u8; 32],
    /// DB-113: the same admission stamp [`PegRequest`] carries — see [`PegInProposal::stamp`].
    pub stamp: u64,
    /// ⭐ §BR-5 — the cash-out TICKET (`cashout_ticket`, constant width): the destination, pay-after and redeem blind under a
    /// key no fewer than two thirds of custody can rebuild. Bound into `redeem_commit` (`cashout_ticket::ticketed_commit`).
    /// O1-FOOTPRINT-REVIEWED: exactly `cashout_ticket::TICKET_BYTES` (`decode` refuses any other width)
    pub ticket: Vec<u8>,
    /// §BR-5 — the requester's sealed leg envelopes, one per custodian (the destination kind, leg blind, change clue,
    /// pay-after — no key share since §BR-9a step c).
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SEALED_MAX envelopes of request_sealed_len() each (`decode` refuses wider)
    pub ticket_envelopes: Vec<([u8; 32], Vec<u8>)>,
    /// ⭐ §BR-9a step (c) — the ONE epoch ciphertext encapsulating the ticket key (its hash is bound into `redeem_commit`).
    /// O1-FOOTPRINT-REVIEWED: exactly `epoch_key::CT_BYTES` (`decode` refuses any other width)
    pub epoch_ct: Vec<u8>,
}

/// ONE custodian's signature over a [`PegOutProposal`]'s statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegOutAttestation {
    pub usdm_nullifier: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_PUBKEY_MAX (`decode` refuses wider)
    pub pubkey: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SIG_MAX (`decode` refuses wider)
    pub sig: Vec<u8>,
}

/// The peg-out twin of [`PendingProposal`].
#[derive(Clone, Debug)]
pub struct PendingOutProposal {
    pub proposal: PegOutProposal,
    pub delta: Option<PegOutDelta>,
    pub authored: bool,
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SEALED_MAX (dedup per custodian; ingest refuses past it)
    pub attestations: Vec<crate::psm::MintAttestor>,
    pub first_seen_ms: u64,
    pub last_broadcast_ms: u64,
}

/// Seal a peg-out delta to one custodian — the same envelope as [`seal_delta_to`] (release in the first
/// amount slot, burn in the second, the destination in the address slot).
#[must_use]
pub fn seal_out_delta_to(custodian_ek: &[u8], d: &PegOutDelta) -> Option<Vec<u8>> {
    seal_delta_to(
        custodian_ek,
        &PegInDelta {
            deposit_value: d.release,
            mint: d.burn,
            reserve_address: d.redeem_to.clone(),
            // DB-110: the peg-out leg never used this slot; the redeem-address blind rides it, so the sealed
            // envelope's wire is unchanged and every custodian can re-derive the chain's `redeem_commit`.
            d_blind: d.r_blind,
            pay_after: d.pay_after,
            sweep: None,
        },
    )
}

/// Open a peg-out envelope sealed by [`seal_out_delta_to`].
#[must_use]
pub fn open_out_delta(custodian_dk: &[u8], blob: &[u8]) -> Option<PegOutDelta> {
    let d = open_delta(custodian_dk, blob)?;
    Some(PegOutDelta {
        release: d.deposit_value,
        burn: d.mint,
        redeem_to: d.reserve_address,
        r_blind: d.d_blind,
        pay_after: d.pay_after,
    })
}

/// ⭐⭐⭐ DB-113 (2026-09-19) — THE PROPOSAL LANES PAY THE SAME ADMISSION STAMP A TRANSACTION PAYS.
///
/// `PegRequest` has carried `stamp` since the lane was built, and the two PROPOSAL messages that travel the
/// same mesh did not. That asymmetry was the whole spam surface: a `PegOutAttestReq` is bytes anyone can
/// craft, every node that decodes one records a gathering slot for it and every bonded custodian runs the
/// signature work, so proposals were free to mint and expensive to receive. Holding them to the pool's live
/// requirement costs a flooder exactly what a flood of transactions costs, which is the bound the rest of
/// this node already relies on — no cap, no eviction, no ageing, and nothing an honest redeem can fail.
///
/// The preimage is the SIGNED STATEMENT plus the sealed envelopes: the statement is what a custodian signs
/// and what the slot dedups on, so one grind buys exactly one proposal, and a relayed copy carries the
/// stamp its author paid for rather than needing a fresh one at every hop.
fn proposal_stamp_work(domain: &[u8], statement: &[u8], sealed: &[([u8; 32], Vec<u8>)], stamp: u64) -> u32 {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(blake3::hash(statement).as_bytes());
    for (id, blob) in sealed {
        h.update(id);
        h.update(blake3::hash(blob).as_bytes());
    }
    let mut buf = Vec::with_capacity(72);
    buf.extend_from_slice(h.finalize().as_bytes());
    buf.extend_from_slice(&stamp.to_le_bytes());
    buf.extend_from_slice(crate::params::process_network_id().as_bytes());
    crate::mempool::leading_zero_bits(blake3::hash(&buf).as_bytes())
}

/// Grind `stamp` until `work(stamp) >= bits`, the same loop [`PegRequest::stamp_to`] runs.
fn grind_proposal_stamp(
    domain: &[u8],
    statement: &[u8],
    sealed: &[([u8; 32], Vec<u8>)],
    bits: u32,
) -> u64 {
    let mut s = 0u64;
    loop {
        if proposal_stamp_work(domain, statement, sealed, s) >= bits {
            return s;
        }
        s = s.wrapping_add(1);
    }
}

impl PegInProposal {
    /// The leading-zero bits this proposal's stamp actually buys.
    #[must_use]
    pub fn stamp_work(&self) -> u32 {
        proposal_stamp_work(
            b"MUSD/peg-in-proposal/stamp/v1",
            &self.statement(),
            &self.sealed,
            self.stamp,
        )
    }

    /// Grind the admission stamp to `bits` — the executor pays this once, at authoring time.
    pub fn stamp_to(&mut self, bits: u32) {
        self.stamp = grind_proposal_stamp(
            b"MUSD/peg-in-proposal/stamp/v1",
            &self.statement(),
            &self.sealed,
            bits,
        );
    }
}

impl PegOutProposal {
    /// The leading-zero bits this proposal's stamp actually buys.
    #[must_use]
    pub fn stamp_work(&self) -> u32 {
        proposal_stamp_work(
            b"MUSD/peg-out-proposal/stamp/v1",
            &self.statement(),
            &self.sealed,
            self.stamp,
        )
    }

    /// Grind the admission stamp to `bits` — the executor pays this once, at authoring time.
    pub fn stamp_to(&mut self, bits: u32) {
        self.stamp = grind_proposal_stamp(
            b"MUSD/peg-out-proposal/stamp/v1",
            &self.statement(),
            &self.sealed,
            bits,
        );
    }
}

impl PegOutProposal {
    /// The statement every custodian signs — `musdm.peg.out.conf.v3`, nonce-bound like the peg-in's.
    /// DB-110: the destination rides as a COMMITMENT; the address itself is in the sealed opening only.
    #[must_use]
    pub fn statement(&self) -> Vec<u8> {
        crate::peg::peg_out_confidential_msg(
            &self.usdm_nullifier,
            &self.new_reserve_commit,
            &self.new_minted_commit,
            // v6: the ticketed commitment bound to the ticket parts this proposal carries; v7: and to its sealed legs
            &crate::peg_out_tx::signed_redeem_commit(&self.redeem_commit, &self.ticket, &self.ticket_envelopes, &self.epoch_ct, &self.sealed),
            &self.nonce,
            &self.leaf_commit,
            &self.change_owner,
            // DB-365: the change's COMMITMENT is the out1 this proposal's burn carrier binds — the value every custodian
            // verifies the carrier against before it signs — so the signature names one change note.
            &crate::spend_frontier::leaf_to_cm_bytes(self.out1_cm),
        )
    }

    #[must_use]
    pub fn commits(&self) -> (Digest4, Digest4) {
        (self.new_reserve_commit, self.new_minted_commit)
    }

    #[must_use]
    pub fn envelope_for(&self, custodian_id: &[u8; 32]) -> Option<&[u8]> {
        self.sealed
            .iter()
            .find(|(id, _)| id == custodian_id)
            .map(|(_, b)| b.as_slice())
    }

    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Bounded decode: sealed count, envelope width, destination width and both carriers are each held to
    /// their protocol constants; a proposal outside them is refused before anything reads it.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let p: Self = crate::chain_object::decode_exact(bytes)?;
        if p.sealed.len() > PEG_ATTEST_SEALED_MAX {
            return None;
        }
        if p.sealed.iter().any(|(_, b)| b.len() != sealed_len()) {
            return None;
        }
        if p.ticket.len() != crate::cashout_ticket::TICKET_BYTES
            || p.ticket_envelopes.is_empty()
            || p.ticket_envelopes.len() > PEG_ATTEST_SEALED_MAX
            || p.ticket_envelopes.iter().any(|(_, b)| b.len() != request_sealed_len())
            || p.epoch_ct.len() != crate::epoch_key::CT_BYTES
        {
            return None; // §BR-5: a cash-out without its whole ticket is not a cash-out
        }
        if p.burn_carrier.is_empty() || p.burn_carrier.len() > PEG_ATTEST_CARRIER_MAX {
            return None;
        }
        if p.membership_carrier.len() > PEG_ATTEST_CARRIER_MAX
            || p.membership_tip.len() > PEG_ATTEST_TIP_MAX
        {
            return None;
        }
        Some(p)
    }
}

impl PegOutAttestation {
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let a: Self = crate::chain_object::decode_exact(bytes)?;
        if a.pubkey.is_empty()
            || a.sig.is_empty()
            || a.pubkey.len() > PEG_ATTEST_PUBKEY_MAX
            || a.sig.len() > PEG_ATTEST_SIG_MAX
        {
            return None;
        }
        Some(a)
    }

    #[must_use]
    pub fn as_attestor(&self) -> crate::psm::MintAttestor {
        crate::psm::MintAttestor {
            pubkey: self.pubkey.clone(),
            sig: self.sig.clone(),
        }
    }
}

impl PegInAttestation {
    #[must_use]
    pub fn slot_key(&self) -> [u8; 32] {
        slot_key_for(self.asset_id, &self.deposit_id)
    }
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let a: Self = crate::chain_object::decode_exact(bytes)?;
        if a.pubkey.is_empty()
            || a.sig.is_empty()
            || a.pubkey.len() > PEG_ATTEST_PUBKEY_MAX
            || a.sig.len() > PEG_ATTEST_SIG_MAX
        {
            return None;
        }
        Some(a)
    }

    /// The attestor as the ledger's threshold tally reads it.
    #[must_use]
    pub fn as_attestor(&self) -> crate::psm::MintAttestor {
        crate::psm::MintAttestor {
            pubkey: self.pubkey.clone(),
            sig: self.sig.clone(),
        }
    }
}

#[must_use]
pub fn slot_key_for(asset_id: u32, deposit_id: &[u8; 32]) -> [u8; 32] {
    // every BRIDGE ledger (native and Monero's) mints through the PegIn lane, keyed by the deposit id itself — the key its
    // replay set (`confidential_deposit_ids`), its pending slots and its publish cache all share
    if crate::peg::PegLedger::is_bridge_ledger(asset_id) {
        *deposit_id
    } else {
        crate::peg::wrapped_deposit_key(asset_id, deposit_id)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// DB-77 (2026-09-19) — THE CUSTODIAL REQUEST: ANY NODE MINTS, REDEEMS OR WRAPS.
//
// MEASURED before this existed (real-node runs 83–86): `/peg_in_execute`, `/wrapped_mint_execute` and
// `/peg_out_execute` answered NOT_A_CUSTODIAN on every node without a bridge signer, so a wallet whose
// node held no seat could neither mint nor redeem — a funds-EGRESS liveness hole (the user's money is
// spendable but not withdrawable) that every settled bridge design avoids.
//
// BORROWED-FROM (cited, not re-derived): tBTC v2's `revealDeposit` — the depositor's request is a chain
// message ANYONE can send; the signer group observes it and acts. THORChain — every node observes the
// external chain and posts its own observation; the state machine mints/releases at the 2/3 threshold.
// Liquid (Blockstream) — the peg-out is an ordinary transaction any node relays; the functionaries watch
// chain state and release. In all three the REQUEST is public data the mesh relays and the CUSTODIANS act
// on chain state, so the requester needs no custodial key. This is that shape:
//
//   wallet ──/peg_*_execute──▶ its OWN node (any node): verifies what needs no secret, SEALS the rest per
//   custodian, records the request, gossips `WireMsg::PegRequest` ──▶ every node relays once (dedup by id)
//   ──▶ each bonded custodian opens ITS envelope, checks its own watcher / the burn proof, proposes from
//   ITS OWN opening (the existing attestation lane gathers the ≥2/3 signatures) ──▶ the runtime tick
//   publishes the chain object once the threshold is met (lowest-id attestor first, the rest back off)
//   ──▶ a block carries it ──▶ every node applies it from the block; the wallet polls chain state.
//
// PRIVACY (the digital-cash cardinal): the mesh relays PROOF MATERIAL the chain will carry anyway (the
// sealed note, the validity carriers, the nullifier, the membership carrier) and CIPHERTEXT for everything
// else: the amounts, the external address (reserve or payout) and the owner's discovery keys ride ML-KEM-768
// sealed per custodian in a FIXED-size body, so a relaying node learns nothing a block would not tell it.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

/// A native USDm peg-in (a confirmed external deposit → a minted USDm note).
pub const PEG_REQUEST_IN: u8 = 0;
/// A native peg-out (a burned USDm note → an external release to the sealed payout address).
pub const PEG_REQUEST_OUT: u8 = 1;
/// A wrapped-asset mint (a confirmed external deposit → a note in a registered wrapped asset).
pub const PEG_REQUEST_WRAPPED: u8 = 2;
/// ⭐ §BR-3 17.6 — a private stake / claim / unstake (`stake_tx`): the staker's own carriers and notes, the reward and its
/// blind sealed per custodian. Any one bonded custodian executes it (`Node::execute_stake`: the stakers' pool supply step
/// needs the custodians' paid-out opening) — no attestation round; the block applies it on every node.
pub const PEG_REQUEST_STAKE: u8 = 3;
/// A sealed note payload the request carries (mint note or change note); the note codec's own width.
pub const PEG_REQUEST_NOTE_MAX: usize = 4096;
/// A deletion witness (cm + copath) for the burned note; UNS_DEPTH digests bounded.
pub const PEG_REQUEST_WITNESS_MAX: usize = 64 * 1024;
/// The requester's node re-gossips its own request at this cadence until the chain settles it.
pub const PEG_REQUEST_REBROADCAST_MS: u64 = 10_000;
/// A custodian that is NOT the lowest-id attestor waits this long for the elected publisher before it
/// publishes itself (the chain applies exactly one; a duplicate is `Replay`, so this is only economy).
pub const PEG_PUBLISH_BACKOFF_MS: u64 = 30_000;
/// ⭐ DB-273 §19 L1 — the owner is the note's OLI clue (`oli::tag_clue_bytes_v2`, `omr::Clue::BYTES`), the one type every
/// owner-named object carries; the sealed body reserves this fixed width for it.
pub const PEG_REQUEST_OWNER_CLUE_MAX: usize = crate::peg_in_tx::OWNER_CLUE_MAX;
/// The FIXED sealed-body width: two u128 amounts, one length-prefixed address, the length-prefixed owner clue and the
/// mint blind. Constant so a relaying node cannot tell a small request from a large one.
/// cons: none — 608 B SMALLER per custodian envelope than the (bucket 32 + len 2 + ek 1,184) it replaces.
pub const PEG_REQUEST_BODY_BYTES: usize =
    16 + 16 + 1 + PEG_ATTEST_ADDRESS_MAX + 2 + PEG_REQUEST_OWNER_CLUE_MAX + crate::spend_frontier::DIGEST_LANE_BYTES + 8 // §BR-1: + pay_after
        + SWEEP_AUTH_BYTES; // §BR-2: + the co-signed deposit's sweep authorization

#[must_use]
pub fn request_sealed_len() -> usize {
    crate::pqkem::ciphertext_len() + PEG_ATTEST_TAG_BYTES + PEG_REQUEST_BODY_BYTES
}

/// What only the custodians may read. `value_a`/`value_b` are (deposit, mint) for a mint and
/// (burn, release) for a redeem; `address` is the reserve address watched for a deposit or the payout
/// address for a release; `owner_clue` is the credited (mint / wrapped) or change (redeem) note's OLI clue — the
/// custodians publish a recipient that COMMITS to it (`peg::peg_in_recipient`), so the owner is signed before anything
/// mints (DB-273 §17 condition 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestSecret {
    pub value_a: u128,
    pub value_b: u128,
    pub address: String,
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_REQUEST_OWNER_CLUE_MAX (one clue; `seal_request_to` and `open_request` refuse
    /// wider, and an EMPTY one — a note nobody could ever find)
    pub owner_clue: Vec<u8>,
    /// DB-80: the mint-delta commitment blind (peg-in / wrapped mint), eight field lanes; zero on a redeem.
    pub d_blind: Digest4,
    /// §BR-1: on a redeem, the earliest chain height the piece may be paid at (the wallet's privacy-delay draw); zero
    /// on a mint.
    pub pay_after: u64,
    /// §BR-2: on a Bitcoin mint request, the depositor's sweep authorization; `None` otherwise.
    pub sweep: Option<SweepAuth>,
}

fn request_stream_key(ss: &[u8]) -> [u8; 32] {
    let mut kh = blake3::Hasher::new();
    kh.update(b"MUSD/peg-request/secret-key/v1");
    kh.update(ss);
    *kh.finalize().as_bytes()
}

fn request_keystream(key: &[u8; 32], ct: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"MUSD/peg-request/stream/v1");
    h.update(ct);
    let mut out = vec![0u8; PEG_REQUEST_BODY_BYTES];
    h.finalize_xof().fill(&mut out);
    out
}

fn request_tag_of(ss: &[u8], body: &[u8]) -> [u8; PEG_ATTEST_TAG_BYTES] {
    let mut th = blake3::Hasher::new();
    th.update(b"MUSD/peg-request/tag/v1");
    th.update(ss);
    th.update(body);
    let mut t = [0u8; PEG_ATTEST_TAG_BYTES];
    t.copy_from_slice(&th.finalize().as_bytes()[..PEG_ATTEST_TAG_BYTES]);
    t
}

/// Seal a request's secret to ONE custodian's ML-KEM-768 encapsulation key. The body is fixed-width and
/// the keystream is bound to the fresh ciphertext, so two seals of one secret never share bytes.
#[must_use]
pub fn seal_request_to(custodian_ek: &[u8], s: &RequestSecret) -> Option<Vec<u8>> {
    let addr = s.address.as_bytes();
    if addr.len() > PEG_ATTEST_ADDRESS_MAX
        || s.owner_clue.is_empty()
        || s.owner_clue.len() > PEG_REQUEST_OWNER_CLUE_MAX
    {
        return None;
    }
    let (ss, ct) = crate::pqkem::encapsulate(custodian_ek)?;
    let mut body = Vec::with_capacity(PEG_REQUEST_BODY_BYTES);
    body.extend_from_slice(&s.value_a.to_le_bytes());
    body.extend_from_slice(&s.value_b.to_le_bytes());
    body.push(addr.len() as u8);
    body.extend_from_slice(addr);
    body.resize(16 + 16 + 1 + PEG_ATTEST_ADDRESS_MAX, 0);
    body.extend_from_slice(&(s.owner_clue.len() as u16).to_le_bytes());
    body.extend_from_slice(&s.owner_clue);
    body.resize(16 + 16 + 1 + PEG_ATTEST_ADDRESS_MAX + 2 + PEG_REQUEST_OWNER_CLUE_MAX, 0);
    body.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&s.d_blind));
    body.extend_from_slice(&s.pay_after.to_le_bytes());
    SweepAuth::encode_opt(s.sweep.as_ref(), &mut body);
    body.resize(PEG_REQUEST_BODY_BYTES, 0);
    let ks = request_keystream(&request_stream_key(&ss), &ct);
    for (b, k) in body.iter_mut().zip(ks.iter()) {
        *b ^= k;
    }
    let tag = request_tag_of(&ss, &body);
    let mut out = Vec::with_capacity(request_sealed_len());
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&body);
    Some(out)
}

/// Open a sealed request secret with THIS custodian's decapsulation key; `None` for anyone else's
/// envelope, a forged tag, or a malformed body (fail-closed — nothing partial is returned).
#[must_use]
pub fn open_request(custodian_dk: &[u8], blob: &[u8]) -> Option<RequestSecret> {
    if blob.len() != request_sealed_len() {
        return None;
    }
    let ct_len = crate::pqkem::ciphertext_len();
    let ct = &blob[..ct_len];
    let tag = &blob[ct_len..ct_len + PEG_ATTEST_TAG_BYTES];
    let sealed_body = &blob[ct_len + PEG_ATTEST_TAG_BYTES..];
    let ss = crate::pqkem::decapsulate(ct, custodian_dk)?;
    if request_tag_of(&ss, sealed_body) != tag {
        return None;
    }
    let ks = request_keystream(&request_stream_key(&ss), ct);
    let body: Vec<u8> = sealed_body.iter().zip(ks.iter()).map(|(b, k)| b ^ k).collect();
    let mut a = [0u8; 16];
    a.copy_from_slice(&body[..16]);
    let mut b = [0u8; 16];
    b.copy_from_slice(&body[16..32]);
    let alen = body[32] as usize;
    if alen > PEG_ATTEST_ADDRESS_MAX {
        return None;
    }
    let address = String::from_utf8(body[33..33 + alen].to_vec()).ok()?;
    let off = 16 + 16 + 1 + PEG_ATTEST_ADDRESS_MAX;
    let clue_len = u16::from_le_bytes([body[off], body[off + 1]]) as usize;
    if clue_len == 0 || clue_len > PEG_REQUEST_OWNER_CLUE_MAX {
        return None;
    }
    let owner_clue = body[off + 2..off + 2 + clue_len].to_vec();
    let boff = off + 2 + PEG_REQUEST_OWNER_CLUE_MAX;
    let d_blind = crate::spend_frontier::digest_from_lane_bytes(&body[boff..boff + crate::spend_frontier::DIGEST_LANE_BYTES])?;
    let poff = boff + crate::spend_frontier::DIGEST_LANE_BYTES;
    let pay_after = u64::from_le_bytes(body[poff..poff + 8].try_into().ok()?);
    let sweep = SweepAuth::decode_opt(&body[poff + 8..])?;
    Some(RequestSecret {
        sweep,
        pay_after,
        value_a: u128::from_le_bytes(a),
        value_b: u128::from_le_bytes(b),
        address,
        owner_clue,
        d_blind,
    })
}

/// The request itself — what any node publishes and every node relays once. Cleartext fields are the
/// proof material the chain object will carry; `sealed` holds one [`RequestSecret`] envelope per bonded
/// custodian. `id` is the deposit id (mint / wrapped) or the burned note's nullifier (redeem): the key
/// every node dedups and every custodian's pending slot is filed under (wrapped: [`slot_key_for`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegRequest {
    pub kind: u8,
    pub asset_id: u32,
    pub id: [u8; 32],
    pub recipient: [u8; 32],
    /// The minted note (mint / wrapped) or the change note (redeem).
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_REQUEST_NOTE_MAX (`decode` refuses wider)
    pub note_payload: Vec<u8>,
    /// The mint-validity carrier (mint / wrapped) or the burn carrier (redeem).
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_CARRIER_MAX (`decode` refuses wider)
    pub carrier: Vec<u8>,
    pub out0_cm: Digest4,
    pub out1_cm: Digest4,
    /// DB-80: the committed mint delta a peg-in / wrapped request's mint-validity carrier binds to
    /// (zero on a redeem). Public; the amount is not.
    pub delta_commit: Digest4,
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_CARRIER_MAX (`decode` refuses wider)
    pub membership_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_TIP_MAX (`decode` refuses wider)
    pub membership_tip: Vec<u8>,
    pub leaf_commit: Digest4,
    /// One sealed [`RequestSecret`] per bonded custodian, keyed by custodian id.
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SEALED_MAX envelopes of request_sealed_len() each (`decode` refuses wider)
    pub sealed: Vec<([u8; 32], Vec<u8>)>,
    /// The same admission stamp a pooled transaction carries (`required_stamp_bits`), so a flood of
    /// requests costs the flooder what a flood of transactions would.
    pub stamp: u64,
    /// ⭐ §BR-5 — on a redeem, the cash-out TICKET (the destination under a two-thirds key; `recipient` carries the TICKETED
    /// redeem commitment the quorum signs). Empty on every other kind.
    /// O1-FOOTPRINT-REVIEWED: exactly `cashout_ticket::TICKET_BYTES` on a redeem, empty otherwise (`decode` refuses else)
    pub ticket: Vec<u8>,
    /// ⭐ §BR-9a step (c) — on a redeem, the ONE epoch ciphertext encapsulating the ticket key. Empty on every other kind.
    /// O1-FOOTPRINT-REVIEWED: exactly `epoch_key::CT_BYTES` on a redeem, empty otherwise (`decode` refuses else)
    pub epoch_ct: Vec<u8>,
    /// ⭐ §BR-4 B4-2 — on a mint that opens a debt unit, the unit half (public; the unit open carries all of it).
    #[serde(default)]
    pub unit: Option<crate::unit_open_tx::UnitPart>,
}

impl PegRequest {
    #[must_use]
    pub fn slot_key(&self) -> [u8; 32] {
        if self.kind == PEG_REQUEST_WRAPPED {
            slot_key_for(self.asset_id, &self.id)
        } else {
            self.id
        }
    }
    #[must_use]
    pub fn envelope_for(&self, custodian_id: &[u8; 32]) -> Option<&[u8]> {
        self.sealed
            .iter()
            .find(|(id, _)| id == custodian_id)
            .map(|(_, b)| b.as_slice())
    }
    /// The stamp's preimage: everything but the stamp, hashed — so the grind cannot be shared across
    /// requests and a relayed copy carries the same stamp the requester paid for.
    #[must_use]
    pub fn stamp_preimage(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/peg-request/stamp/v1");
        h.update(&[self.kind]);
        h.update(&self.asset_id.to_le_bytes());
        h.update(&self.id);
        if let Some(u) = &self.unit {
            // §BR-4 B4-2: the unit half is paid for by the same stamp
            h.update(b"unit");
            h.update(&u.claim.deposit_id());
            h.update(blake3::hash(&u.unit_carrier).as_bytes());
        }
        h.update(&self.recipient);
        h.update(blake3::hash(&self.note_payload).as_bytes());
        h.update(blake3::hash(&self.carrier).as_bytes());
        for x in self.delta_commit {
            h.update(&x.to_le_bytes());
        }
        for (id, blob) in &self.sealed {
            h.update(id);
            h.update(blake3::hash(blob).as_bytes());
        }
        *h.finalize().as_bytes()
    }
    #[must_use]
    pub fn stamp_work(&self) -> u32 {
        let mut buf = Vec::with_capacity(72);
        buf.extend_from_slice(&self.stamp_preimage());
        buf.extend_from_slice(&self.stamp.to_le_bytes());
        buf.extend_from_slice(crate::params::process_network_id().as_bytes());
        crate::mempool::leading_zero_bits(blake3::hash(&buf).as_bytes())
    }
    /// Grind the admission stamp to `bits` (milliseconds at the pool's live requirement).
    pub fn stamp_to(&mut self, bits: u32) {
        let mut s = 0u64;
        loop {
            self.stamp = s;
            if self.stamp_work() >= bits {
                return;
            }
            s = s.wrapping_add(1);
        }
    }
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    /// Decode with every width bounded — a request wider than the lane admits is not a request.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let r: Self = crate::chain_object::decode_exact(bytes)?;
        // §19.4: the escrow kind is gone with the custody-spent escrow it served (B5-d) — a claim is an ordinary redeem request
        if !matches!(r.kind, PEG_REQUEST_IN | PEG_REQUEST_OUT | PEG_REQUEST_WRAPPED | PEG_REQUEST_STAKE) {
            return None;
        }
        if r.sealed.is_empty() || r.sealed.len() > PEG_ATTEST_SEALED_MAX {
            return None;
        }
        if r.sealed.iter().any(|(_, b)| b.len() != request_sealed_len()) {
            return None;
        }
        if r.note_payload.is_empty() || r.note_payload.len() > PEG_REQUEST_NOTE_MAX {
            return None;
        }
        // §BR-4 B4-2: a unit half rides only a native mint, bounded like the unit open it becomes (its carrier is checked by
        // the custodians before they propose, `UnitPart::verifies`)
        if let Some(u) = &r.unit {
            let bounded = r.kind == PEG_REQUEST_IN
                && r.asset_id == crate::peg::NATIVE_PEG_ASSET_ID
                && u.unit_note.len() == crate::cover::PQ_NOTE_BYTES
                && !u.unit_clue.is_empty()
                && u.unit_clue.len() <= crate::peg_in_tx::OWNER_CLUE_MAX
                && !u.unit_carrier.is_empty()
                && u.unit_carrier.len() <= crate::unit_open_tx::UNIT_CARRIER_MAX;
            if !bounded {
                return None;
            }
        }
        if r.carrier.is_empty() || r.carrier.len() > PEG_ATTEST_CARRIER_MAX {
            return None;
        }
        if r.membership_carrier.len() > PEG_ATTEST_CARRIER_MAX
            || r.membership_tip.len() > PEG_ATTEST_TIP_MAX
        {
            return None;
        }
        // §BR-5: a redeem carries its whole ticket (constant width, one epoch ciphertext); no other kind carries one
        let ticketed = r.ticket.len() == crate::cashout_ticket::TICKET_BYTES && r.epoch_ct.len() == crate::epoch_key::CT_BYTES;
        let unticketed = r.ticket.is_empty() && r.epoch_ct.is_empty();
        let wants_ticket = r.kind == PEG_REQUEST_OUT;
        if (wants_ticket && !ticketed) || (!wants_ticket && !unticketed) {
            return None;
        }
        if matches!(r.kind, PEG_REQUEST_OUT | PEG_REQUEST_STAKE) && r.membership_carrier.is_empty() {
            return None; // a redeem must name the note it burns: its membership cross-bind (Z1: the
                         // burn itself is the nullifier `id`, proven at the pool door like every spend)
        }
        // ⛔ THE LEDGER A REQUEST NAMES (lane defi, 2026-11-01): a bridge deposit, a redeem and a stake name asset 0 (the
        // deposit's ledger is its sealed address's chain, the cash-out's its sealed kind — §19.5b keeps both out of public view);
        // a wrapped mint never names a bridge ledger. MEASURED: a Monero deposit's request (asset 1) was refused HERE
        // ("NOT_ONE_ENCODING") since 9ee96cd; it now names asset 0 like every bridge deposit.
        // §19.5b: a deposit request names asset 0 for BOTH bridge ledgers — the ledger is the sealed address's chain, never a
        // public field a relaying node could read
        let ledger_ok = match r.kind {
            PEG_REQUEST_IN => r.asset_id == crate::peg::NATIVE_PEG_ASSET_ID,
            PEG_REQUEST_WRAPPED => !crate::peg::PegLedger::is_bridge_ledger(r.asset_id),
            // §18.14: a coin note's burn names its coin; every other burn asset 0
            PEG_REQUEST_OUT => r.asset_id == crate::peg::NATIVE_PEG_ASSET_ID || crate::peg::PegLedger::is_coin_ledger(r.asset_id),
            _ => r.asset_id == crate::peg::NATIVE_PEG_ASSET_ID,
        };
        if !ledger_ok {
            return None;
        }
        Some(r)
    }
}

/// What a node keeps per request it has seen: the requester's own node keeps the request (to re-gossip
/// until the chain settles it); a custodian keeps the request AND its opened secret (to propose and to
/// publish); any other relaying node keeps only this header (dedup + status), never the payload.
#[derive(Clone, Debug)]
pub struct PegRequestSlot {
    pub kind: u8,
    pub asset_id: u32,
    /// The request's own id (deposit id / nullifier) — the slot key is derived from it and the kind.
    pub id: [u8; 32],
    pub own: bool,
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_CARRIER_MAX-bounded request fields (`PegRequest::decode`), one per slot, PEG_ATTEST_PENDING_MAX slots
    pub request: Option<PegRequest>,
    pub secret: Option<RequestSecret>,
    pub first_seen_ms: u64,
    pub last_broadcast_ms: u64,
    /// The custodian's own retry clock for ACTING on this request (open, confirm, propose) — separate from
    /// the requester's re-gossip clock above. One field for both (2026-09-19) meant a custodian's OWN
    /// wallet request was re-gossiped and, in the same tick, judged "just acted on": the lane never
    /// proposed it and only the door's inline action ever minted an own request.
    pub last_action_ms: u64,
    /// This custodian has proposed from this request (its authored attestation slot exists).
    pub proposed: bool,
    /// Set when the threshold was met but another custodian is the elected publisher.
    pub publish_after_ms: Option<u64>,
    /// This node published the chain object (or saw the chain apply it) — nothing more to do.
    pub done: bool,
    /// ⭐ §19.4 — the requester's own RELAY MOMENT (unix ms; 0 = at once): a cash-out claim is first gossiped then, a moment
    /// its wallet drew uniformly between the claim's proof and its batch, so custody cannot group one user's pieces by when
    /// they arrived. Never set on a request this node did not author.
    pub relay_after_ms: u64,
    /// ⭐ A-F78 — every custodian id this node has seen an envelope for, over every variant of this request. A variant that
    /// names an id outside it is relayed (`Node::peg_request_note` answers fresh): a requester whose vault gained a member
    /// re-seals (the doors, [`covers`]) and the new member's envelope must cross every relay that saw the first variant.
    /// O1-FOOTPRINT-REVIEWED: at most PEG_SEEN_IDS_MAX ids a slot, PEG_ATTEST_PENDING_MAX slots.
    pub seen_ids: Vec<[u8; 32]>,
    /// ⭐ A-F78 — the requester's OWN secret (this node's own wallet asked; set by `Node::peg_request_own_secret`, never from
    /// the mesh), so its re-gossip tick can seal the same request to a custodian that joined the vault since. VOLATILE (RAM,
    /// like the slot): a restart loses it and the wallet's next repeat sets it again.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the node's own wallet's secret, held where the door already held it; never sent.
    pub own_secret: Option<RequestSecret>,
}

/// ⭐ A-F78 — the custodian ids a slot remembers (ids past it are no longer relay-worthy: the bound a hostile stream of made-up
/// ids meets). DERIVED: the most envelopes one request may carry (`PEG_ATTEST_SEALED_MAX`, enforced by `decode`), so every
/// id of the widest honest re-seal fits. Cost: at most 256 × 32 B = 8 KB a slot, × PEG_ATTEST_PENDING_MAX (64) = 512 KB.
pub const PEG_SEEN_IDS_MAX: usize = PEG_ATTEST_SEALED_MAX;

/// ⭐ A-F78 (lane af58, 2026-11-16) — THE ONE COVERAGE TEST every request door asks before it answers a repeat GATHERING: does
/// the request this node already holds carry an envelope for every custodian it would seal to NOW? A request is sealed once,
/// to the custodians the requester's node held at that moment; a deposit requested while a custodian joined its vault was
/// sealed to the old set, the new member could open nothing, and every repeat answered GATHERING without looking (MEASURED
/// 2026-11-16 07:00, rig speed5wrap: "sealed to 1 custodian(s)", the other logged "names no envelope this custodian opens"
/// 264 times, nothing minted in 96 fold steps). When this is false the door seals again to the current set and publishes
/// that variant; its body is the same, so it is the same mint, and only the requester's own door ever replaces its stored
/// request (a relayed variant never does — a junk envelope cannot displace the honest one the requester re-gossips).
/// AI RESISTANT: (b) code — and the mint itself still needs the quorum's signatures over the same body, so a variant can
/// only add an envelope, never change what is minted. SCALE: O(members) per repeat; constant in height and bonded set.
#[must_use]
pub fn covers(stored: Option<&PegRequest>, ids: &[[u8; 32]]) -> bool {
    stored.is_some_and(|r| ids.iter().all(|id| r.sealed.iter().any(|(s, _)| s == id)))
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn a_peg_out_envelope_opens_only_for_its_custodian_and_a_proposal_is_bounded() {
        let (ek, dk) = crate::pqkem::keypair();
        let (_ek2, dk2) = crate::pqkem::keypair();
        let d = PegOutDelta {
            release: 700,
            burn: 700,
            redeem_to: crate::btc_tx::address_for_test_seed(crate::bridge::btc_hrp(), b"redeem-leg-test"),
            // DB-110: the destination blind rides the sealed envelope beside the address itself.
            r_blind: crate::spend_frontier::cm_bytes_to_root(&crate::spend_frontier::canonical_filler_bytes(0x5a)).unwrap(),
            pay_after: 0,
        };
        let blob = seal_out_delta_to(&ek, &d).expect("seals");
        assert_eq!(open_out_delta(&dk, &blob).as_ref(), Some(&d));
        assert!(open_out_delta(&dk2, &blob).is_none(), "another custodian opens nothing");
        let zero = usdm_decider::poseidon2_compress::zero_digest();
        let mut p = PegOutProposal {
            usdm_nullifier: [7u8; 32],
            redeem_commit: crate::peg::redeem_commit(d.redeem_to.as_bytes(), d.pay_after, &d.r_blind),
            new_reserve_commit: zero,
            new_minted_commit: zero,
            nonce: [1u8; 32],
            sealed: vec![([2u8; 32], blob)],
            burn_carrier: vec![1u8; 64],
            out0_cm: zero,
            out1_cm: zero,
            membership_carrier: vec![2u8; 16],
            membership_tip: vec![3u8; 96],
            leaf_commit: zero,
            change_owner: [4u8; 32],
            stamp: 0,
            ticket: crate::peg_out_tx::ticket_parts_for_test().0,
            ticket_envelopes: crate::peg_out_tx::ticket_parts_for_test().1,
            epoch_ct: crate::peg_out_tx::ticket_parts_for_test().2,
        };
        assert_eq!(PegOutProposal::decode(&p.wire()).as_ref(), Some(&p), "round-trips");
        p.burn_carrier = vec![0u8; PEG_ATTEST_CARRIER_MAX + 1];
        assert!(PegOutProposal::decode(&p.wire()).is_none(), "a carrier past the pillar bound is refused");
        p.burn_carrier = Vec::new();
        assert!(PegOutProposal::decode(&p.wire()).is_none(), "no burn evidence, no proposal");
    }

    fn delta() -> PegInDelta {
        PegInDelta {
            deposit_value: 3_000,
            mint: 2_000,
            reserve_address: crate::btc_tx::address_for_test_seed(crate::bridge::btc_hrp(), b"seat-journey-reserve"),
            d_blind: usdm_decider::poseidon2_compress::lanes_of(&[0xd, 0xb, 0x8, 0x0]),
            pay_after: 0,
            sweep: None,
        }
    }

    /// The envelope opens for its custodian and for nobody else; the length never depends on the address.
    #[test]
    fn a_sealed_delta_opens_only_for_its_custodian_and_has_one_length() {
        let (ek, dk) = crate::pqkem::keypair();
        let (_ek2, dk2) = crate::pqkem::keypair();
        let blob = seal_delta_to(&ek, &delta()).expect("seals");
        assert_eq!(blob.len(), sealed_len());
        assert_eq!(open_delta(&dk, &blob), Some(delta()));
        assert_eq!(open_delta(&dk2, &blob), None, "a foreign custodian learns nothing");
        let long = PegInDelta {
            reserve_address: "4".repeat(95),
            ..delta()
        };
        let blob2 = seal_delta_to(&ek, &long).expect("a Monero-length address seals");
        assert_eq!(blob2.len(), blob.len(), "constant envelope length whatever the address");
        assert_eq!(open_delta(&dk, &blob2), Some(long));
        let too_long = PegInDelta {
            reserve_address: "x".repeat(PEG_ATTEST_ADDRESS_MAX + 1),
            ..delta()
        };
        assert!(seal_delta_to(&ek, &too_long).is_none(), "over-long address refused, never truncated");
    }

    /// A flipped byte anywhere in the envelope is refused — the tag binds the body under the shared secret.
    #[test]
    fn a_tampered_envelope_is_refused() {
        let (ek, dk) = crate::pqkem::keypair();
        let blob = seal_delta_to(&ek, &delta()).expect("seals");
        for at in [0usize, crate::pqkem::ciphertext_len(), blob.len() - 1] {
            let mut t = blob.clone();
            t[at] ^= 1;
            assert_eq!(open_delta(&dk, &t), None, "tamper at {at} must not open");
        }
    }

    /// Wire round-trip for both messages, and the shape bounds a decode enforces.
    #[test]
    fn proposal_and_attestation_round_trip_and_bound() {
        let (ek, _dk) = crate::pqkem::keypair();
        let p = PegInProposal {
            asset_id: 0,
            deposit_id: [7u8; 32],
            recipient: [9u8; 32],
            new_reserve_commit: usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            new_minted_commit: usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
            delta_commit: usdm_decider::poseidon2_compress::lanes_of(&[9, 10, 11, 12]),
            nonce: [4u8; 32],
            sealed: vec![([3u8; 32], seal_delta_to(&ek, &delta()).unwrap())],
            stamp: 0,
            unit: None,
        };
        assert_eq!(PegInProposal::decode(&p.wire()), Some(p.clone()));
        assert!(p.envelope_for(&[3u8; 32]).is_some());
        assert!(p.envelope_for(&[4u8; 32]).is_none());
        let mut bad = p.clone();
        bad.sealed[0].1.pop();
        assert!(PegInProposal::decode(&bad.wire()).is_none(), "a short envelope is refused at decode");
        let mut wide = p.clone();
        wide.sealed = (0..=PEG_ATTEST_SEALED_MAX)
            .map(|i| ([i as u8; 32], p.sealed[0].1.clone()))
            .collect();
        assert!(PegInProposal::decode(&wide.wire()).is_none(), "more envelopes than custodians refused");
        let a = PegInAttestation {
            asset_id: 0,
            deposit_id: [7u8; 32],
            pubkey: vec![1u8; 1952],
            sig: vec![2u8; 3309],
        };
        assert_eq!(PegInAttestation::decode(&a.wire()), Some(a.clone()));
        let mut hollow = a.clone();
        hollow.sig.clear();
        assert!(PegInAttestation::decode(&hollow.wire()).is_none());
    }
}
