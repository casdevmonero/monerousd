// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **A BRIDGE CREDIT IS A TRANSACTION** — so a user's deposit exists for the NETWORK the moment the gates
//! pass, not whenever the particular node that accepted it next wins a block.
//!
//! THE GAP, MEASURED not read (`a_bridge_credit_reaches_a_peer_only_once_the_accepting_node_produces`):
//! with the accepting node quiet a peer does not hold the deposit; after that node produces ONE block and
//! the peer grafts, it does. So PRODUCTION, not verification, stands between a user and their money being
//! visible. A joiner or a freshly restarted node holds a confirmed deposit nobody else can see.
//!
//! AND THE TRAP THAT DECIDES THE DESIGN, also measured
//! (`crediting_the_same_note_commitment_twice_credits_it_once`, RED): recording one commitment twice puts
//! it in the produced block TWICE. There is no idempotency beneath `record_note_payload` — today the only
//! thing between a repeated credit and inflation is that each CALLER carries its own replay gate (the peg's
//! spent-deposit set, the burn set). That is a sharp edge: any new caller that double-writes mints twice.
//!
//! So this credit is idempotent BY COMMITMENT at the door: a node that already holds the note does nothing
//! rather than crediting again. That makes "publish it and let any producer include it" safe even while the
//! accepting node has staged its own copy, and it closes the sharp edge for every future caller at once.
//!
//! WHAT IS NOT HERE, deliberately: the peg gates. Replay refusal, the attestor threshold, the confidential
//! reserve/minted carrier and the amount-in-asset binding all live in `peg.rs` / `node.rs` and are already
//! sound — this module never re-implements them, it carries their OUTPUT so every node applies the same
//! credit the same way.

use serde::{Deserialize, Serialize};

/// A credited deposit, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeCreditTx {
    /// The foreign-chain deposit this settles, so a node can name what it applied and a duplicate is
    /// recognisable as the same DEPOSIT rather than merely the same bytes.
    pub deposit_id: [u8; 32],
    /// The asset credited — USDm's tag for a peg-in, the wrapped asset's tag for a wrapped mint.
    pub asset_tag: [u64; 3],
    pub amount: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note payload, `PQ_NOTE_BYTES`.
    pub note: Vec<u8>,
    /// ⭐ DB-273 §17 — the OWNER of the credited note, as its OLI locator clue (`tag_clue_bytes_v2` for a fresh index of
    /// the owner's wallet); empty = no owner (a fixture, or the node's own demo balance). It replaces the old
    /// `(bucket, ek)` account target, a per-wallet constant every payment repeated. It lives INSIDE the object, so the
    /// frame's id binds it, and the quorum's message binds its digest ([`crate::peg::PegLedger::bridge_credit_msg`]).
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one clue, `omr::Clue::BYTES`.
    #[serde(default)]
    pub owner_clue: Vec<u8>,
    /// ⭐⭐⭐ THE BONDED ATTESTATIONS THAT AUTHORISE THIS CREDIT — the answer to "WHO may issue one".
    ///
    /// ⛔⛔⛔ THE HOLE THIS CLOSES, quoted from the census that filed it: *"`chain_object::admissible`
    /// decodes, compares the amount to the genesis allowance and returns true — NOTHING asks who may
    /// issue a credit. Its own doc says the bonded threshold arm 'is not wired yet'. Safe on a
    /// value-bearing network ONLY because the allowance is 0 there, which is a fail-closed default and
    /// not an authority."* Being UNSATISFIABLE is not being AUTHORISED — and it also meant the bridge
    /// could not credit a deposit on mainnet at all.
    ///
    /// ⭐ BORROWED FROM THE CLASS BESIDE IT, NOT INVENTED: `Class::WrappedMint` is attested exactly this
    /// way — attestations over a domain-separated message, tallied at APPLY by the ONE bonded quorum
    /// function (`peg::threshold_ok`), with `admissible` staying structural. Same division of labour,
    /// same tally, same bound constant, same wire shape.
    ///
    /// ⭐ `(pubkey, sig)` PAIRS, NOT A SECOND `MintAttestor` ENCODING. `MintAttestor` is deliberately not
    /// `serde`; every attested class carries the pairs and rebuilds the struct at its reader (see
    /// [`Self::attestor_structs`] and `wrapped_mint_tx::decode`). One codec per wire family.
    ///
    /// `serde(default)` so a frame written before this field decodes to an EMPTY attestation set — which
    /// authorises nothing and is refused on any network whose allowance cannot cover it. Fail-closed by
    /// construction rather than by remembering to check a version.
    ///
    /// O1-FOOTPRINT-REVIEWED: bounded by MAX_CREDIT_ATTESTORS (= params::DAG_WIDTH_CEILING), refused at
    /// the decode exactly as wrapped_mint_tx::MAX_MINT_ATTESTORS is — a protocol constant, identical on
    /// every network, with no term in chain height, block count, note count or age.
    #[serde(default)]
    pub attestors: Vec<(Vec<u8>, Vec<u8>)>,
}

/// ⭐ THE ATTESTOR BOUND, THE SAME CONSTANT EVERY OTHER ATTESTED CLASS USES.
///
/// ⛔ ENFORCED AT THE DECODE, not merely declared: `decode` refuses a frame carrying more than this, so
/// an attacker cannot make a door do unbounded signature work by sending a long vector — the §9.6 Q5
/// shape `peg::threshold_ok` documents at its own loop. Sharing `DAG_WIDTH_CEILING` with
/// `wrapped_mint_tx`, `wrapped_asset_tx` and `liquidation_tx` keeps ONE number for "how many attestors
/// can matter" instead of four that drift apart.
pub const MAX_CREDIT_ATTESTORS: usize = crate::params::DAG_WIDTH_CEILING;

impl BridgeCreditTx {
    /// The commitment this credit creates, read the way every other path reads one. ONE encoding.
    pub fn note_cm(&self) -> Option<[u8; 32]> {
        if self.note.len() < 32 {
            return None;
        }
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&self.note[..32]);
        Some(cm)
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// The bytes a transaction carries: the encoding FRAMED with its class (`MAGIC || CLASS || payload`),
    /// so a receiver judges it by the right rule. v32 (item 8c): the bare `encode()` used to ride the
    /// wire, which no dispatcher could classify — `chain_object::admissible` never even reached a
    /// BridgeCredit arm for it.
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::BridgeCredit, &self.encode())
    }

    /// Refuses rather than guesses: a zero amount is not a credit, and a note too short to carry a
    /// commitment credits nobody.
    /// The carried pairs as the attestor structs the ONE quorum tally takes.
    ///
    /// ⛔ REBUILT AT THE READER, exactly as `wrapped_mint_tx::decode` rebuilds them — the wire carries
    /// `(pubkey, sig)` bytes and the tally takes types, so there is no second `MintAttestor` encoding
    /// anywhere. One codec per wire family.
    pub fn attestor_structs(&self) -> Vec<crate::psm::MintAttestor> {
        self.attestors
            .iter()
            .map(|(pubkey, sig)| crate::psm::MintAttestor {
                pubkey: pubkey.clone(),
                sig: sig.clone(),
            })
            .collect()
    }

    pub fn decode(bytes: &[u8]) -> Option<BridgeCreditTx> {
        let c: BridgeCreditTx = crate::chain_object::decode_exact(bytes)?;
        if c.amount == 0 || c.note.len() < 32 {
            return None;
        }
        // ⛔⛔⛔ §BR-13 item 4 — SAT HAS EXACTLY THREE DOORS (the block reward, the genesis set, a conserving spend). A credit
        // names its own asset tag, and nothing refused the SAT tag: on an open-mint network (or with a bonded quorum) a
        // bridge credit was a FOURTH door that minted SAT outside the 21M proof. Refused at the decode, so every door that
        // reads a credit (pool, graft, fold, justifier) refuses it on every node.
        if c.asset_tag == crate::satoshi::asset_tag() {
            return None;
        }
        // ⛔ THE ATTESTOR BOUND IS A DECODE RULE. Refusing here — before any caller can hand the vector
        // to a signature loop — is what makes MAX_CREDIT_ATTESTORS a bound rather than a comment.
        if c.attestors.len() > MAX_CREDIT_ATTESTORS {
            return None;
        }
        Some(c)
    }

    /// The transaction a bridge RPC admits once the peg gates have passed. Publishing this is what lets ANY
    /// producer include the deposit, which is the whole availability fix.
    ///
    /// v32 (item 8c) — THREE defects fixed here, each pinned by the admission tests:
    ///   * the blob is the FRAMED wire form (`wire()`), so `chain_object::admissible` reads its class —
    ///     the bare postcard blob used to fall through to the send gate and die `InvalidProof`;
    ///   * the anti-spam stamp is GROUND to `stamp_bits` (the caller passes the pool's
    ///     `required_stamp_bits()`), where the old `pow_stamp: 0` lost to the live floor of 8 bits and
    ///     the credit could never occupy a pool slot;
    ///   * ⭐ DB-273 §17: the owner's locator clue rides `note_clues` in the SAME wire encoding the staging reader
    ///     parses (`stage_carried_note_clues`: cm(32)‖len(2,LE)‖clue), derived from the object's OWN
    ///     `owner_clue` — one source, bound by the frame's id and the quorum's message — so a node that never saw
    ///     the RPC files the note for its owner exactly like a paid one. No account target is written: the
    ///     per-wallet (bucket, ek) constant is gone from this class.
    pub fn as_pq_tx(&self, stamp_bits: u32) -> crate::mempool::PqTx {
        let blob = self.wire();
        let account_targets = Vec::new();
        let mut note_clues = Vec::new();
        if let Some(cm) = self.note_cm() {
            if !self.owner_clue.is_empty() {
                note_clues.extend_from_slice(&cm);
                note_clues.extend_from_slice(&(self.owner_clue.len() as u16).to_le_bytes());
                note_clues.extend_from_slice(&self.owner_clue);
            }
        }
        let mut tx = crate::mempool::PqTx {
            clock_ms: 0,
            id: crate::mempool::PqTx::content_id(&blob),
            weight: blob.len() as u32,
            blob,
            // A credit MINTS; it burns nothing, so it publishes no nullifier. The burn belongs to a peg-OUT.
            nullifiers: Vec::new(),
            pow_stamp: 0,
            note_clues,
            account_targets,
            output_notes: self.note.clone(),
            stake_notes: Vec::new(),
            bond_notes: Vec::new(),
            nullifier_witnesses: Vec::new(),
            nullifier_absence: Vec::new(),
            membership_carrier: Vec::new(),
            membership_leaf_commit: [0u8; 32],
            membership_tip: Vec::new(),
            membership_folded_through: 0,
            spend_or_decoy: Vec::new(),
            member_carrier: Vec::new(),
            member_tuple: Vec::new(),
        };
        // Grind the anti-spam stamp exactly as a real submit does (leading-zero bits of
        // blake3(id || pow_stamp || network_id)). Bounded work BY CONSTRUCTION: 2^stamp_bits expected
        // tries — ~256 at the live floor of 8 bits, milliseconds; the adaptive ceiling (24 bits under a
        // full pool) is the caller's number to pass.
        let mut s = 0u64;
        loop {
            tx.pow_stamp = s;
            if tx.stamp_work() >= stamp_bits {
                break;
            }
            s = s.wrapping_add(1);
        }
        tx
    }
}

/// What a node did with a credit it found in a block.
#[derive(Debug, PartialEq, Eq)]
pub enum CreditApply {
    /// Not a bridge credit — left alone.
    NotCredit,
    /// Credited: this many units, as one note.
    Credited(u64),
    /// Already held. NOT an error and NOT a second credit — the whole point.
    AlreadyHeld,
}

/// ⭐⭐⭐ THE ONE MINT-AUTHORITY TALLY FOR A FRAMED CREDIT — read by EVERY door, computed nowhere else.
///
/// ⛔⛔⛔ WHY THIS IS A FUNCTION AND NOT AN `if` INSIDE ONE DOOR. `chain_object::admissible` is the rule
/// three separate doors ask: the POOL door (`accept_verified`), the GRAFT door (`graft_admitted_notes`
/// and the §BA credit-set binds beside it) and this reconciliation door. A credit that one door admits
/// and another refuses is a FORK — the pins
/// `a_rogue_mainnet_producer_cannot_mint_a_credit_through_the_block_body` and
/// `a_credit_the_mint_door_refuses_cannot_retire_a_staged_credit_on_either_party` exist precisely
/// because the authority once bound only the pool door, so a producer that skipped its own door minted
/// on every honest peer at graft. The amount bound and the quorum bound must therefore travel TOGETHER
/// into every door, which is what `admissible`'s fourth parameter is for and what this function fills.
///
/// ⭐ BORROWED FROM THE CLASS BESIDE IT: `Class::WrappedMint` is authorised exactly this way, and the
/// tally is the SAME function — `peg::threshold_ok`. Distinct attestors only, unbonded keys contribute
/// zero, the signature count is bounded by the bonded set, and the message is domain-separated
/// (`peg::PegLedger::bridge_credit_msg`) binding the deposit id, asset, amount AND note commitment, so
/// an attestation over one credit cannot be replayed onto another.
///
/// ⛔ THE QUORUM IS READ FROM THE CHAIN'S OWN BONDED SET, NEVER FROM THE OBJECT. The caller passes the
/// validator set THIS node has folded from the chain; the credit supplies only signatures. That is the
/// difference between an authority and a self-assertion, and it is why this is not the local-decides-
/// truth trap: every honest node folds the same bonded set from the same blocks, so every honest node
/// computes the same verdict on the same bytes.
///
/// ⛔ FAIL-CLOSED ON EVERY MISSING PIECE — not a credit, no note commitment, no attestors, or a tally
/// short of ≥2/3 all return `false`. A frame written before the `attestors` field existed decodes to
/// zero attestors and is therefore unattested, with nothing to remember.
/// ⭐⭐⭐ DB-274 P4 (§8.11) — THE GRAFT-TIME ARM: the credit's SHAPE, never its weight. A block's credit is judged for
/// weight exactly once, at its FOLD, in the step's canonical pre-state ([`credit_attested_by_bonded_quorum`] against the
/// folded set, `Node::credit_decide_at_fold`). At graft every node holds a DIFFERENT folded set (each at its own fold
/// cursor), so a weight verdict there is a per-node verdict: the fork P4 exists to remove (§8.10 H1).
///
/// ⛔ NO SIGNATURE IS VERIFIED HERE, on purpose (§8.11 item 5). `peg::tally_attestors` verifies a signature only for a
/// DISTINCT, BONDED attestor — its bounded-work fix (§9.6 Q5). A set-free graft cannot know who is bonded, so verifying
/// every signature here would let a producer pack unbonded attestors and buy one ML-DSA verify each. The fold's tally
/// keeps the bound.
///
/// True for a framed `BridgeCredit` that decodes, names its note commitment and carries at least one attestor. False
/// for anything else — fail-closed, like the weight arm.
pub fn credit_structurally_attested(blob: &[u8]) -> bool {
    let Some((class, payload)) = crate::chain_object::unframe(blob) else {
        return false;
    };
    if class != crate::chain_object::Class::BridgeCredit {
        return false;
    }
    let Some(c) = BridgeCreditTx::decode(payload) else {
        return false;
    };
    c.note_cm().is_some() && !c.attestor_structs().is_empty()
}

pub fn credit_attested_by_bonded_quorum(
    quorum: &dyn crate::psm::BondQuorum,
    blob: &[u8],
) -> bool {
    let Some((class, payload)) = crate::chain_object::unframe(blob) else {
        return false;
    };
    if class != crate::chain_object::Class::BridgeCredit {
        return false;
    }
    let Some(c) = BridgeCreditTx::decode(payload) else {
        return false;
    };
    let Some(cm) = c.note_cm() else {
        // Fixed string — by construction no tag, cm, amount, key or owner can appear in it.
        eprintln!(
            "[credit-auth] ⛔ UNATTESTED: this credit carries no note commitment, so there is nothing \
             for a bonded quorum to have attested."
        );
        return false;
    };
    // DB-273 §17: the message binds the owner clue, so a copy whose owner a relay stripped or replaced fails here.
    let msg = crate::peg::PegLedger::bridge_credit_msg(&c.deposit_id, &c.asset_tag, c.amount, &cm, &c.owner_clue);
    let attestors = c.attestor_structs();
    if !crate::peg::threshold_ok(quorum, &crate::pqauth::MlDsaVerifier, &msg, &attestors) {
        // Privacy: a COUNT and a branch name only — never a note, amount, key or owner.
        eprintln!(
            "[credit-auth] ⛔ UNATTESTED: {} attestation(s) do not reach the ≥2/3 bonded threshold.",
            attestors.len()
        );
        return false;
    }
    eprintln!(
        "[credit-auth] ATTESTED: a ≥2/3 bonded quorum signs this credit over its domain-separated \
         message — the mainnet mint authority."
    );
    true
}


/// The `(cm, amount)` a framed `BridgeCredit` names, or `None` for any other blob. `amount` is the object's type, u64.
pub fn credit_cm_and_amount(blob: &[u8]) -> Option<([u8; 32], u64)> {
    let (class, payload) = crate::chain_object::unframe(blob)?;
    if class != crate::chain_object::Class::BridgeCredit {
        return None;
    }
    let c = BridgeCreditTx::decode(payload)?;
    Some((c.note_cm()?, c.amount))
}
