// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ §BR-6 — THE ENTRY MIX: Bitcoin deposits no coordinator can link, with post-quantum credentials
//! (docs/BR-6-ENTRY-MIX-SPEC-20261029.md).
//!
//! BORROWED: WabiSabi's three-phase credential CoinJoin (Ficsór et al. 2021, Wasabi 2.0) — input registration issues a
//! credential, output registration redeems it over a different circuit, signing happens only when a user sees its own
//! outputs; Whirlpool's single-denomination pool (every mixed output of a round is the same ladder unit, so the anonymity
//! set of one output is every credential of the round); Wasabi's per-input miner fee (each input pays for the bytes it
//! adds, the coordinator takes nothing); BIP 69 ordering (inputs and outputs sorted, so the transaction's order says
//! nothing about registration order). NOVEL: the credential is a MonerousD NOTE in the round's one 256-leaf record, and
//! redeeming it is the chain's own post-quantum spend machinery — the one-step membership carrier against the record
//! root the coordinator ML-DSA-signed, the nullifier refused by the round's set, and a burn (the bond-validity carrier)
//! whose burned output's opening is derived from the output script, so a credential pays exactly one registered output.
//!
//! Units: a credential's value is `denom + PROTOCOL_FEE_ATOMIC` in the note field — the ladder unit in satoshis plus the
//! spend circuit's flat fee, so the burn's arithmetic (`value_in = out0 + out1 + fee`, `out0 = denom` welded public)
//! forces `out1 = 0`: one credential, one output, nothing left over. The coordinator computes every credential
//! commitment itself from the user's opening, so the value inside is the round's, never the user's claim.
//!
//! What the coordinator learns: the input set (it is on Bitcoin anyway), each input's credential count (a multiple of
//! the round's one denomination), and the output set. Never the mapping: the membership proof hides the leaf, the
//! nullifier needs the credential's `nk`, and the leaf commitment carries the prover's fresh blind.
//! DIGITAL-CASH-PRIVACY-REVIEWED: nothing in an output registration is a function of the credential's leaf that a
//! party without the credential's secrets can evaluate (census: `a_coordinator_holding_every_registration_cannot_single_out_the_input_behind_an_output`).
//!
//! CLASSICAL-CRYPTO-EXEMPT: the input ownership proof and the transaction signatures are Bitcoin's own BIP-340 signatures
//! over Bitcoin coins — the foreign chain admits only its own primitive; nothing of MonerousD's own soundness rests on them.

use crate::btc_tx::{self, Payout, TxIn, TxOut};
use crate::spend_frontier::{cm_bytes_to_root, digest_to_lane_bytes, leaf_to_cm_bytes, Digest4};
use std::collections::{BTreeMap, BTreeSet};
use usdm_decider::whir_rec_block as w;

/// One record: the in-block shape every membership proof is built for (`IN_BLOCK_DEPTH` = 8 levels).
pub const ROUND_LEAVES: usize = 256;
pub const ROUND_DEPTH: usize = usdm_decider::note_membership_air::IN_BLOCK_DEPTH;
/// The most credentials one input may draw (all of the round's one denomination): one whole decimal digit of the coin, so
/// a digit of 9 mixes in ONE round (8 would split it into 8 + 1 across two rounds — an extra fee and a rarer pattern;
/// caught by the wallet pin `a_coin_mixes_one_decimal_digit_per_round_down_to_the_smallest_ladder_unit`).
pub const CREDS_PER_INPUT_MAX: usize = 9;
/// The fewest inputs a round signs with: the peg pool's batch floor (an anonymity set of one is no mix).
pub const ROUND_INPUTS_MIN: usize = crate::peg_pool::BATCH_MIN;
/// A taproot scriptPubKey: `OP_1 <32>`.
pub const P2TR_SPK_BYTES: usize = 34;
/// Virtual sizes the per-input fee is charged on (BIP 341 key-path input ≈ 57.5 vB, a P2TR output 43 vB, the transaction
/// overhead ~10.5 vB — each input pays the overhead once, so every input pays the same base and the surplus is the miner's).
pub const KEYPATH_INPUT_VBYTES: u64 = 58;
pub const P2TR_OUTPUT_VBYTES: u64 = 43;
pub const TX_OVERHEAD_VBYTES: u64 = 11;
/// Bitcoin Core's dust threshold for a P2TR output: a smaller change is not made (it goes to the miner).
pub const P2TR_DUST_SATS: u64 = 330;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Inputs,
    Outputs,
    Signing,
    Broadcast,
}

/// The round's public terms: its id, its one denomination, its fee rate and its coordinator's ML-DSA key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundTerms {
    pub round_id: [u8; 32],
    pub denom: u64,
    pub fee_rate_sat_vb: u64,
    pub coordinator_pk: Vec<u8>,
}

impl RoundTerms {
    /// A round's terms; `nonce` is the coordinator's fresh draw, so two rounds never share an id.
    #[must_use]
    pub fn new(coordinator_pk: Vec<u8>, denom: u64, fee_rate_sat_vb: u64, nonce: &[u8; 32]) -> Option<RoundTerms> {
        if !crate::peg_pool::is_denom(denom) || fee_rate_sat_vb == 0 {
            return None;
        }
        let mut h = blake3::Hasher::new_derive_key("MUSD/entry-mix/round-id/v1");
        h.update(&crate::pqauth::pubkey_id(&coordinator_pk));
        h.update(nonce);
        h.update(&denom.to_le_bytes());
        h.update(&fee_rate_sat_vb.to_le_bytes());
        Some(RoundTerms { round_id: *h.finalize().as_bytes(), denom, fee_rate_sat_vb, coordinator_pk })
    }

    /// The credential's note value: the denomination plus the spend circuit's flat fee (see the module doc).
    #[must_use]
    pub fn credential_value(&self) -> u64 {
        self.denom + w::PROTOCOL_FEE_ATOMIC
    }

    /// What an input with `creds` credentials pays the miner, with or without a change output.
    #[must_use]
    pub fn input_fee(&self, creds: usize, change: bool) -> u64 {
        let vb = TX_OVERHEAD_VBYTES + KEYPATH_INPUT_VBYTES + (creds as u64 + u64::from(change)) * P2TR_OUTPUT_VBYTES;
        vb * self.fee_rate_sat_vb
    }

    /// The change an input of `value` with `creds` credentials gets back to its own vault, or `None` when the remainder
    /// is under the dust floor (it is the miner's), or `Err` when the input cannot pay its denominations and fee.
    pub fn change_for(&self, value: u64, creds: usize) -> Result<Option<u64>, &'static str> {
        let mixed = self.denom.checked_mul(creds as u64).ok_or("overflow")?;
        let with_change = value.checked_sub(mixed).and_then(|v| v.checked_sub(self.input_fee(creds, true)));
        match with_change {
            Some(c) if c >= P2TR_DUST_SATS => Ok(Some(c)),
            _ => {
                value.checked_sub(mixed).and_then(|v| v.checked_sub(self.input_fee(creds, false))).ok_or("the input does not cover its denominations and its fee")?;
                Ok(None)
            }
        }
    }
}

/// A credential's commitment for the round: `asset_note_cm(denom + fee, USDm, opening)`. The coordinator computes it from
/// the user's opening `o = P(spk, seed)` (the opening hides the credential's `(ask, nk)`).
#[must_use]
pub fn credential_cm(terms: &RoundTerms, opening: &Digest4) -> Digest4 {
    w::asset_note_cm(terms.credential_value(), w::USDM_ASSET_TAG, *opening)
}

/// The burned output's opening a credential redeemed for `spk` carries: a function of the round and the output script,
/// so a burn proven for one output cannot register another (refuter 3).
#[must_use]
pub fn output_opening(terms: &RoundTerms, spk: &[u8]) -> Digest4 {
    let mut pre = Vec::with_capacity(24 + 32 + spk.len());
    pre.extend_from_slice(b"MUSD/entry-mix/out/v1");
    pre.extend_from_slice(&terms.round_id);
    pre.extend_from_slice(spk);
    crate::spend_frontier::cm_bytes_to_leaf(crate::hash::Hash32::hash(&pre).as_bytes())
}

/// The burned output's commitment for `spk`.
#[must_use]
pub fn output_cm(terms: &RoundTerms, spk: &[u8]) -> Digest4 {
    w::asset_note_cm(terms.denom, w::USDM_ASSET_TAG, output_opening(terms, spk))
}

fn pair(l: Digest4, r: Digest4) -> Digest4 {
    usdm_decider::nullifier_insert_air::poseidon_pair_native(l, r)
}

/// The record's root over its leaves, zero-padded to [`ROUND_LEAVES`] (the in-block tree: `parent = P(left, right)`).
#[must_use]
pub fn record_root(leaves: &[Digest4]) -> Digest4 {
    let mut level: Vec<Digest4> = (0..ROUND_LEAVES).map(|i| leaves.get(i).copied().unwrap_or(usdm_decider::poseidon2_compress::ZERO_DIGEST)).collect();
    while level.len() > 1 {
        level = level.chunks(2).map(|c| pair(c[0], c[1])).collect();
    }
    level[0]
}

/// The copath of leaf `index` (siblings bottom-up, `dirs[l]` = the walk is a right child at level `l`), as
/// `refold_in_block` reads it.
#[must_use]
pub fn record_copath(leaves: &[Digest4], index: usize) -> Option<(Vec<Digest4>, Vec<bool>)> {
    if index >= ROUND_LEAVES || index >= leaves.len() {
        return None;
    }
    let mut level: Vec<Digest4> = (0..ROUND_LEAVES).map(|i| leaves.get(i).copied().unwrap_or(usdm_decider::poseidon2_compress::ZERO_DIGEST)).collect();
    let (mut sib, mut dirs, mut at) = (Vec::with_capacity(ROUND_DEPTH), Vec::with_capacity(ROUND_DEPTH), index);
    while level.len() > 1 {
        sib.push(level[at ^ 1]);
        dirs.push(at & 1 == 1);
        level = level.chunks(2).map(|c| pair(c[0], c[1])).collect();
        at >>= 1;
    }
    Some((sib, dirs))
}

/// The message the coordinator ML-DSA-signs over the round's record: round id, root and leaf count.
#[must_use]
pub fn record_msg(round_id: &[u8; 32], root: &Digest4, leaves: usize) -> Vec<u8> {
    let mut m = Vec::with_capacity(28 + 32 + 32 + 8);
    m.extend_from_slice(b"MUSD/entry-mix/record/v1");
    m.extend_from_slice(round_id);
    m.extend_from_slice(&leaf_to_cm_bytes(*root));
    m.extend_from_slice(&(leaves as u64).to_le_bytes());
    m
}

/// ⛔ EQUIVOCATION PROOF: two valid coordinator signatures over DIFFERENT records of one round. A coordinator that hands
/// different users different records (to tell them apart by the root their outputs prove against) is caught by any two
/// users comparing what they were served — and the pair is a publicly checkable fault of a bonded custodian.
#[must_use]
pub fn is_equivocation(terms: &RoundTerms, a: (&Digest4, usize, &[u8]), b: (&Digest4, usize, &[u8])) -> bool {
    (a.0 != b.0 || a.1 != b.1)
        && crate::pqauth::ml_dsa_verify(&record_msg(&terms.round_id, a.0, a.1), &terms.coordinator_pk, a.2)
        && crate::pqauth::ml_dsa_verify(&record_msg(&terms.round_id, b.0, b.1), &terms.coordinator_pk, b.2)
}

/// The message an input's owner signs with its coin's key: the round, the coin, every credential opening and the change
/// script — so the coordinator (or anyone on the path) cannot swap a credential or the change for its own.
#[must_use]
pub fn ownership_msg(round_id: &[u8; 32], txid: &[u8; 32], vout: u32, openings: &[Digest4], change_spk: &[u8]) -> [u8; 32] {
    let mut m = Vec::with_capacity(32 + 32 + 4 + 2 + openings.len() * crate::spend_frontier::DIGEST_LANE_BYTES + 2 + change_spk.len());
    m.extend_from_slice(round_id);
    m.extend_from_slice(txid);
    m.extend_from_slice(&vout.to_le_bytes());
    m.extend_from_slice(&(openings.len() as u16).to_le_bytes());
    for o in openings {
        m.extend_from_slice(&digest_to_lane_bytes(o));
    }
    m.extend_from_slice(&(change_spk.len() as u16).to_le_bytes());
    m.extend_from_slice(change_spk);
    btc_tx::tagged_hash(b"MUSD/entry-mix/own/v1", &m)
}

fn is_p2tr(spk: &[u8]) -> bool {
    spk.len() == P2TR_SPK_BYTES && spk[0] == 0x51 && spk[1] == 0x20
}

/// One input registration (phase 1, over its own Tor circuit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputReg {
    pub txid: [u8; 32],
    pub vout: u32,
    /// The credential openings `o_j = P(spk_j, seed_j)`, one per ladder unit this input mixes.
    pub openings: Vec<Digest4>,
    /// The input's own change script (its vault) — empty when the user takes no change. Change is linked to its input by
    /// construction (it is the same owner's unmixed remainder, never deposited); only the denominations are mixed.
    pub change_spk: Vec<u8>,
    /// BIP-340 signature by the coin's own output key over [`ownership_msg`].
    pub own_sig: [u8; 64],
}

/// One output registration (phase 2, over a FRESH Tor circuit): a ladder-unit output to `spk`, paid by a credential the
/// coordinator cannot name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputReg {
    pub spk: Vec<u8>,
    /// The credential's nullifier `P(nk, cm)` (canonical bytes).
    pub nf: [u8; 32],
    /// The cross-bind both proofs carry: `P(P(cm, nf), blind)`.
    pub leaf_commit: Digest4,
    /// The burn's second output (value forced to zero by the arithmetic; its commitment is the prover's).
    pub out1_cm: Digest4,
    /// The burn: the bond-validity carrier with `out0 = denom` welded public and `out0_cm = output_cm(spk)`.
    pub burn: Vec<u8>,
    /// The one-step membership of the credential in the signed record root.
    pub membership: Vec<u8>,
}

/// A coin as Bitcoin holds it: value, scriptPubKey, confirmations.
pub type PrevoutLookup<'a> = &'a dyn Fn(&[u8; 32], u32) -> Option<(u64, Vec<u8>, u64)>;

struct RegisteredInput {
    reg: InputReg,
    value: u64,
    spk: Vec<u8>,
    change: Option<u64>,
    sig: Option<[u8; 64]>,
}

/// ⭐⭐ THE COORDINATOR'S ROUND (node side). Bounded state: at most [`ROUND_LEAVES`] credentials, as many outputs, the
/// inputs that drew them, and the round's nullifier set — all dropped when the round ends (no growth: one round at a time
/// per coordinator).
pub struct Round {
    pub terms: RoundTerms,
    sk: Vec<u8>,
    pub phase: Phase,
    /// O1-FOOTPRINT-REVIEWED: ≤ ROUND_LEAVES / 1 inputs (each draws ≥ 1 credential), freed with the round.
    inputs: BTreeMap<([u8; 32], u32), RegisteredInput>,
    /// O1-FOOTPRINT-REVIEWED: ≤ ROUND_LEAVES by the input door.
    leaves: Vec<Digest4>,
    signed: Option<(Digest4, Vec<u8>)>,
    /// O1-FOOTPRINT-REVIEWED: ≤ ROUND_LEAVES (one per redeemed credential), freed with the round.
    nullifiers: BTreeSet<[u8; 32]>,
    /// O1-FOOTPRINT-REVIEWED: ≤ ROUND_LEAVES.
    outputs: Vec<Vec<u8>>,
    /// Inputs a blame round admits (`None` = any).
    allowed: Option<BTreeSet<([u8; 32], u32)>>,
}

impl Round {
    #[must_use]
    pub fn open(terms: RoundTerms, sk: Vec<u8>) -> Round {
        Round { terms, sk, phase: Phase::Inputs, inputs: BTreeMap::new(), leaves: Vec::new(), signed: None, nullifiers: BTreeSet::new(), outputs: Vec::new(), allowed: None }
    }

    /// The input door. §9.6: (1) PoW — n/a (an off-chain round message; nothing enters a block from here); (2) the coin's
    /// own BIP-340 signature over [`ownership_msg`], verified against the coin's output key as Bitcoin holds it; (3) value —
    /// the credential commitments are computed HERE at the round's value, so no input draws more than its coin pays for
    /// (value ≥ creds·denom + its fee, checked against the coin's confirmed value); (4) replay — one registration per coin
    /// (the outpoint set), a credential cm can appear once (a reused opening is refused); (5) bounded — ≤ 9 credentials
    /// per input, ≤ 256 per round, one signature check; (6) parity — no other door issues credentials.
    pub fn register_input(&mut self, reg: InputReg, prevout: PrevoutLookup) -> Result<(), &'static str> {
        if self.phase != Phase::Inputs {
            return Err("the round is past input registration");
        }
        let op = (reg.txid, reg.vout);
        if self.allowed.as_ref().is_some_and(|a| !a.contains(&op)) {
            return Err("a blame round admits only the inputs that signed the failed round");
        }
        if self.inputs.contains_key(&op) {
            return Err("this coin is already registered in the round");
        }
        if reg.openings.is_empty() || reg.openings.len() > CREDS_PER_INPUT_MAX {
            return Err("an input draws one to eight credentials");
        }
        if self.leaves.len() + reg.openings.len() > ROUND_LEAVES {
            return Err("the round's record is full (join the next round)");
        }
        if !reg.change_spk.is_empty() && !is_p2tr(&reg.change_spk) {
            return Err("change goes to a taproot vault address");
        }
        let (value, spk, confs) = prevout(&reg.txid, reg.vout).ok_or("the coin is not unspent on Bitcoin")?;
        if confs == 0 {
            return Err("the coin is unconfirmed");
        }
        if !is_p2tr(&spk) {
            return Err("only a taproot coin can register (its key proves ownership)");
        }
        let x: [u8; 32] = spk[2..34].try_into().map_err(|_| "spk")?;
        let msg = ownership_msg(&self.terms.round_id, &reg.txid, reg.vout, &reg.openings, &reg.change_spk);
        if !btc_tx::verify_sighash_sig(&x, &msg, &reg.own_sig) { // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own BIP-340 verify of the coin's owner (bridge endpoint)
            return Err("the ownership signature does not verify for this coin");
        }
        let change = self.terms.change_for(value, reg.openings.len())?;
        if change.is_some() && reg.change_spk.is_empty() {
            return Err("this input has change above dust and names no change address");
        }
        let cms: Vec<Digest4> = reg.openings.iter().map(|o| credential_cm(&self.terms, o)).collect();
        let held: BTreeSet<Digest4> = self.leaves.iter().copied().collect();
        let mut fresh = BTreeSet::new();
        if cms.iter().any(|c| held.contains(c) || !fresh.insert(*c)) {
            return Err("a credential opening is reused");
        }
        self.leaves.extend_from_slice(&cms);
        self.inputs.insert(op, RegisteredInput { reg, value, spk, change, sig: None });
        Ok(())
    }

    /// Close input registration: publish the record and sign its root. `Err` under the round's input floor.
    pub fn close_inputs(&mut self) -> Result<(Vec<Digest4>, Digest4, Vec<u8>), &'static str> {
        if self.phase != Phase::Inputs {
            return Err("the round is past input registration");
        }
        if self.inputs.len() < ROUND_INPUTS_MIN {
            return Err("too few inputs for a mix (the round waits or re-opens)");
        }
        let root = record_root(&self.leaves);
        let sig = crate::pqauth::ml_dsa_sign(&record_msg(&self.terms.round_id, &root, self.leaves.len()), &self.sk).ok_or("the coordinator key does not sign")?;
        self.signed = Some((root, sig.clone()));
        self.phase = Phase::Outputs;
        Ok((self.leaves.clone(), root, sig))
    }

    /// The signed record (what every user fetches, from peers, and compares).
    #[must_use]
    pub fn record(&self) -> Option<(Vec<Digest4>, Digest4, Vec<u8>)> {
        self.signed.as_ref().map(|(r, s)| (self.leaves.clone(), *r, s.clone()))
    }

    /// The output door. §9.6: (1) PoW — n/a (an off-chain round message); (2) the burn (bond-validity carrier, the
    /// protocol fee welded) and the one-step membership against THIS round's signed root, cross-bound by one leaf
    /// commitment, both verified here; (3) value — the burn's arithmetic pays exactly one ladder unit to exactly the
    /// registered script (`out0_cm = output_cm(spk)`, `out0 = denom` public, the credential's value fixed by the input
    /// door); (4) replay — the round's nullifier set refuses a second redemption; (5) bounded — two proof verifies, at
    /// most 256 outputs; (6) parity — the cash-out's burn binding (`burn_out_cm`) and the escrow's membership leg.
    pub fn register_output(&mut self, o: OutputReg) -> Result<(), &'static str> {
        if self.phase != Phase::Outputs {
            return Err("the round is not registering outputs");
        }
        let (root, _) = self.signed.clone().ok_or("no signed record")?;
        if !is_p2tr(&o.spk) {
            return Err("an output is a taproot deposit address");
        }
        if self.outputs.iter().any(|s| s == &o.spk) {
            return Err("this output script is already registered (no address reuse)");
        }
        if self.nullifiers.contains(&o.nf) {
            return Err("this credential is already redeemed");
        }
        if self.outputs.len() >= self.leaves.len() {
            return Err("every credential of the round is redeemed");
        }
        let nf = cm_bytes_to_root(&o.nf).ok_or("the nullifier is not a canonical digest")?;
        if !usdm_decider::verify_bond_validity_carrier_with_commit_bytes(&o.burn, output_cm(&self.terms, &o.spk), o.out1_cm, nf, self.terms.denom, o.leaf_commit, w::PROTOCOL_FEE_ATOMIC) {
            return Err("the burn does not prove one ladder unit to this output");
        }
        if !usdm_decider::note_membership_air::verify_note_membership_one_step(&o.membership, o.leaf_commit, nf, root) {
            return Err("the credential is not a member of this round's record");
        }
        self.nullifiers.insert(o.nf);
        self.outputs.push(o.spk);
        Ok(())
    }

    /// Close output registration: the unsigned transaction every user checks before it signs.
    pub fn close_outputs(&mut self) -> Result<Payout, &'static str> {
        if self.phase != Phase::Outputs {
            return Err("the round is not registering outputs");
        }
        self.phase = Phase::Signing;
        self.unsigned_tx()
    }

    /// The round's transaction, BIP 69 ordered: every registered input; one ladder unit per redeemed credential; each
    /// input's change at the amount the input door computed.
    pub fn unsigned_tx(&self) -> Result<Payout, &'static str> {
        let mut inputs: Vec<TxIn> = self
            .inputs
            .values()
            .map(|r| TxIn { txid: r.reg.txid, vout: r.reg.vout, value_sats: r.value, script_pubkey: r.spk.clone(), sequence: 0xffff_fffd })
            .collect();
        inputs.sort_by(|a, b| (a.txid, a.vout).cmp(&(b.txid, b.vout)));
        let mut outputs: Vec<TxOut> = self.outputs.iter().map(|s| TxOut { value_sats: self.terms.denom, script_pubkey: s.clone() }).collect();
        for r in self.inputs.values() {
            if let Some(c) = r.change {
                outputs.push(TxOut { value_sats: c, script_pubkey: r.reg.change_spk.clone() });
            }
        }
        outputs.sort_by(|a, b| (a.value_sats, &a.script_pubkey).cmp(&(b.value_sats, &b.script_pubkey)));
        Ok(Payout { inputs, outputs })
    }

    /// One input's signature (BIP 341 key path over the round's transaction), verified against the coin's key.
    pub fn add_signature(&mut self, txid: &[u8; 32], vout: u32, sig: [u8; 64]) -> Result<(), &'static str> {
        if self.phase != Phase::Signing {
            return Err("the round is not signing");
        }
        let tx = self.unsigned_tx()?;
        let idx = tx.inputs.iter().position(|i| &i.txid == txid && i.vout == vout).ok_or("not an input of this round")?;
        let r = self.inputs.get_mut(&(*txid, vout)).ok_or("not an input of this round")?;
        let x: [u8; 32] = r.spk[2..34].try_into().map_err(|_| "spk")?;
        let sighash = tx.sighash_key_path(idx).ok_or("sighash")?;
        if !btc_tx::verify_sighash_sig(&x, &sighash, &sig) { // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own BIP-340 verify of the coin's signature (bridge endpoint)
            return Err("the signature does not verify for this input");
        }
        r.sig = Some(sig);
        Ok(())
    }

    /// The fully signed transaction (raw), or the coins that have not signed (`Err`): a round with one missing
    /// signature moves nothing — WabiSabi's blame round re-runs it with only the coins that did sign.
    pub fn finalize(&mut self) -> Result<Vec<u8>, Vec<([u8; 32], u32)>> {
        let tx = self.unsigned_tx().map_err(|_| Vec::new())?;
        let mut witnesses = Vec::with_capacity(tx.inputs.len());
        let mut missing = Vec::new();
        for i in &tx.inputs {
            match self.inputs.get(&(i.txid, i.vout)).and_then(|r| r.sig) {
                Some(s) => witnesses.push(vec![s.to_vec()]),
                None => missing.push((i.txid, i.vout)),
            }
        }
        if !missing.is_empty() || self.phase != Phase::Signing {
            return Err(missing);
        }
        self.phase = Phase::Broadcast;
        tx.serialize_with_witness(&witnesses).ok_or_else(Vec::new)
    }

    /// WabiSabi's blame round: a fresh round (new id, fresh credentials) that admits only the coins that signed this one.
    #[must_use]
    pub fn blame_round(&self, nonce: &[u8; 32]) -> Option<Round> {
        let signed: BTreeSet<([u8; 32], u32)> = self.inputs.iter().filter(|(_, r)| r.sig.is_some()).map(|(k, _)| *k).collect();
        let terms = RoundTerms::new(self.terms.coordinator_pk.clone(), self.terms.denom, self.terms.fee_rate_sat_vb, nonce)?;
        let mut r = Round::open(terms, self.sk.clone());
        r.allowed = Some(signed);
        Some(r)
    }
}

// ═══════════════════════════════════ the client half (the wallet's round client, B6-b) ═══════════════════════════════════

/// A credential the wallet drew for one ladder unit: a one-time owner from fresh entropy, held only for the round.
#[derive(Clone, Debug)]
pub struct Credential {
    pub owner: w::NoteOwner,
}

impl Credential {
    /// A fresh one-time owner (`ask`, `nk`, `seed` from the OS CSPRNG). `None` when the OS gives no entropy.
    #[must_use]
    pub fn fresh() -> Option<Credential> {
        Some(Credential { owner: w::NoteOwner { ask: w::fresh_lc_blind()?, nk: w::fresh_lc_blind()?, seed: w::fresh_lc_blind()? } })
    }

    /// What the wallet hands the coordinator at input registration.
    #[must_use]
    pub fn opening(&self) -> Digest4 {
        self.owner.opening()
    }

    #[must_use]
    pub fn cm(&self, terms: &RoundTerms) -> Digest4 {
        credential_cm(terms, &self.opening())
    }
}

/// The wallet signs its input registration with its vault coin's key-path secret (the BIP-86 tweaked scalar).
#[must_use]
pub fn sign_input_registration(terms: &RoundTerms, txid: &[u8; 32], vout: u32, creds: &[Credential], change_spk: &[u8], keypath_secret: &[u8; 32]) -> Option<InputReg> {
    let openings: Vec<Digest4> = creds.iter().map(Credential::opening).collect();
    let msg = ownership_msg(&terms.round_id, txid, vout, &openings, change_spk);
    let aux = crate::cashout_ticket::fresh_entropy(32)?;
    let aux: [u8; 32] = aux.as_slice().try_into().ok()?;
    let own_sig = btc_tx::sign_sighash(keypath_secret, &msg, &aux)?; // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own BIP-340 signature by the coin's owner (bridge endpoint)
    Some(InputReg { txid: *txid, vout, openings, change_spk: change_spk.to_vec(), own_sig })
}

/// The wallet's check of a served record before it proves anything against it: the coordinator's ML-DSA signature over
/// exactly these leaves, and its own credential among them. `Some(index)` when the wallet may redeem.
#[must_use]
pub fn check_record(terms: &RoundTerms, leaves: &[Digest4], root: &Digest4, sig: &[u8], cred: &Credential) -> Option<usize> {
    if leaves.len() > ROUND_LEAVES || record_root(leaves) != *root || !crate::pqauth::ml_dsa_verify(&record_msg(&terms.round_id, root, leaves.len()), &terms.coordinator_pk, sig) {
        return None;
    }
    let cm = cred.cm(terms);
    leaves.iter().position(|l| *l == cm)
}

/// ⭐ Prove one output registration: the burn of `cred` into one ladder unit to `spk`, and its one-step membership in the
/// signed record — both under ONE fresh blind (the cross-bind). `None` when the record does not hold the credential or a
/// proof does not prove (the wallet registers nothing).
#[must_use]
pub fn prove_output(terms: &RoundTerms, leaves: &[Digest4], cred: &Credential, spk: &[u8]) -> Option<OutputReg> {
    if !is_p2tr(spk) {
        return None;
    }
    let cm = cred.cm(terms);
    let index = leaves.iter().position(|l| *l == cm)?;
    let (siblings, dirs) = record_copath(leaves, index)?;
    let root = record_root(leaves);
    let lc_blind = w::fresh_lc_blind()?;
    let wit = w::SpendValidityWitness {
        value_in: terms.credential_value(),
        owner: cred.owner.clone(),
        value_out: terms.denom,
        fee: w::PROTOCOL_FEE_ATOMIC,
        lc_blind,
        out0_value: terms.denom,
        out0_opening: output_opening(terms, spk),
        out1_value: 0,
        out1_opening: w::fresh_lc_blind()?,
    };
    let (burn, out_cms, nf, lc) = w::prove_bond_validity_carrier_with_commit_bytes(&wit, terms.denom)?;
    let membership = usdm_decider::note_membership_air::prove_note_member_step_bytes(cm, &siblings, &dirs, root, nf, lc_blind)?;
    if usdm_decider::note_membership_air::note_leaf_commitment(cm, nf, lc_blind) != lc {
        return None;
    }
    Some(OutputReg { spk: spk.to_vec(), nf: leaf_to_cm_bytes(nf), leaf_commit: lc, out1_cm: out_cms[1], burn, membership })
}

/// ⛔ THE TRUSTLESS SIGNING RULE (refuter 4): the wallet signs its input ONLY when the round's transaction spends its coin
/// at its value and pays every one of its outputs a ladder unit and its change exactly — so a coordinator that drops,
/// alters or redirects one of them gets no signature, and the round moves nothing.
#[must_use]
pub fn may_sign(terms: &RoundTerms, tx: &Payout, coin: (&[u8; 32], u32, u64), my_outputs: &[Vec<u8>], change: Option<(&[u8], u64)>) -> Option<usize> {
    let idx = tx.inputs.iter().position(|i| &i.txid == coin.0 && i.vout == coin.1 && i.value_sats == coin.2)?;
    let mut want: Vec<(u64, Vec<u8>)> = my_outputs.iter().map(|s| (terms.denom, s.clone())).collect();
    if let Some((spk, v)) = change {
        want.push((v, spk.to_vec()));
    }
    let mut have: Vec<(u64, Vec<u8>)> = tx.outputs.iter().map(|o| (o.value_sats, o.script_pubkey.clone())).collect();
    for wnt in want {
        let at = have.iter().position(|h| *h == wnt)?;
        have.swap_remove(at);
    }
    Some(idx)
}

/// The wallet's input signature for the round's transaction (BIP 341 key path).
#[must_use]
pub fn sign_round_input(tx: &Payout, idx: usize, keypath_secret: &[u8; 32]) -> Option<[u8; 64]> {
    let sighash = tx.sighash_key_path(idx)?;
    let aux = crate::cashout_ticket::fresh_entropy(32)?;
    let aux: [u8; 32] = aux.as_slice().try_into().ok()?;
    btc_tx::sign_sighash(keypath_secret, &sighash, &aux) // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own BIP-340 signature over a Bitcoin coin (bridge endpoint)
}

// ═══════════════════════════════════ the wire (node side, B6-a) ═══════════════════════════════════
//
// BORROWED: WabiSabi's transport split — the round's PUBLIC state (terms, the signed record, the unsigned transaction) is
// broadcast to everyone (here: one small flooded announcement per round, like a peg request); every REGISTRATION goes
// point to point to the coordinator over a FRESH Tor circuit (here: the bulk port, `BULK_REQ_KIND_MIX`, dialed on a new
// isolation token per request), so the coordinator cannot join an input registration to an output registration by the
// circuit either arrived on. Flooding registrations instead was measured out: an output registration is ~265 KB (two
// constant-shape proofs), 256 per round × every node × a round per epoch ≈ 37 GB/day per node.

/// The bulk request kind a registration rides (`[24][round id 32][what u8][body]`).
pub const BULK_REQ_KIND_MIX: u8 = 24;
/// The answer page's tag: `MIXANS ‖ H(request) 32 ‖ ok u8 ‖ reason (≤ 120 bytes)`.
pub const MIX_ANSWER_TAG: &[u8; 6] = b"MIXANS";
pub const MIX_REASON_MAX: usize = 120;
/// One epoch of the coordinator rotation: inputs, outputs, signing, broadcast.
pub const MIX_EPOCH_MS: u64 = 150_000;
pub const MIX_INPUTS_END_MS: u64 = 60_000;
pub const MIX_OUTPUTS_END_MS: u64 = 100_000;
pub const MIX_SIGNING_END_MS: u64 = 140_000;
/// The widest coordinator address an announcement carries (a v3 onion is 62 bytes).
pub const MIX_ADDR_MAX: usize = 96;
const WHAT_INPUT: u8 = 1;
const WHAT_OUTPUT: u8 = 2;
const WHAT_SIGN: u8 = 3;

/// How often the epoch's opening view is re-announced while inputs are open (late joiners hear it within this).
pub const MIX_ANNOUNCE_MS: u64 = 30_000;

/// The round nonce of an epoch: a function of the epoch alone, so every wallet DERIVES a round's id (coordinator key,
/// ladder unit, fee rate, epoch) instead of being told it — a coordinator cannot hand two users two ids for one round.
#[must_use]
pub fn epoch_nonce(epoch: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/entry-mix/epoch-nonce/v1");
    h.update(&epoch.to_le_bytes());
    *h.finalize().as_bytes()
}

impl RoundTerms {
    /// The terms of the `denom` round of `epoch` under `coordinator_pk` at `fee_rate_sat_vb`.
    #[must_use]
    pub fn for_epoch(coordinator_pk: Vec<u8>, denom: u64, fee_rate_sat_vb: u64, epoch: u64) -> Option<RoundTerms> {
        RoundTerms::new(coordinator_pk, denom, fee_rate_sat_vb, &epoch_nonce(epoch))
    }
}

/// The epoch and the coordinator for `now_ms`: the bonded custodians (sorted ids) take turns, one epoch each.
#[must_use]
pub fn epoch_coordinator(now_ms: u64, custodians_sorted: &[[u8; 32]]) -> Option<(u64, [u8; 32])> {
    if custodians_sorted.is_empty() {
        return None;
    }
    let epoch = now_ms / MIX_EPOCH_MS;
    Some((epoch, custodians_sorted[(epoch % custodians_sorted.len() as u64) as usize]))
}

struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.i..self.i.checked_add(n)?)?;
        self.i += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|s| u32::from_le_bytes(s.try_into().unwrap_or([0; 4])))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|s| u64::from_le_bytes(s.try_into().unwrap_or([0; 8])))
    }
    fn a32(&mut self) -> Option<[u8; 32]> {
        self.take(32).and_then(|s| s.try_into().ok())
    }
    fn digest(&mut self) -> Option<Digest4> {
        self.take(crate::spend_frontier::DIGEST_LANE_BYTES).and_then(crate::spend_frontier::digest_from_lane_bytes)
    }
    fn bytes16(&mut self, max: usize) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        if n > max {
            return None;
        }
        self.take(n)
    }
    fn bytes32(&mut self, max: usize) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return None;
        }
        self.take(n)
    }
    fn done(&self) -> bool {
        self.i == self.b.len()
    }
}

fn put16(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
}
fn put32(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

/// The widest proof a registration may carry (the blinded committed carriers are ~132 KB; 1 MiB bounds a hostile one).
pub const MIX_PROOF_MAX: usize = 1 << 20;

/// A registration as the coordinator receives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MixRequest {
    Input(InputReg),
    Output(OutputReg),
    Sign { txid: [u8; 32], vout: u32, sig: [u8; 64] },
}

impl MixRequest {
    /// `[24][round id][what][body]` — exact length, every width bounded.
    #[must_use]
    pub fn encode(&self, round_id: &[u8; 32]) -> Vec<u8> {
        let mut out = vec![BULK_REQ_KIND_MIX];
        out.extend_from_slice(round_id);
        match self {
            MixRequest::Input(r) => {
                out.push(WHAT_INPUT);
                out.extend_from_slice(&r.txid);
                out.extend_from_slice(&r.vout.to_le_bytes());
                out.push(r.openings.len() as u8);
                for o in &r.openings {
                    out.extend_from_slice(&digest_to_lane_bytes(o));
                }
                put16(&mut out, &r.change_spk);
                out.extend_from_slice(&r.own_sig);
            }
            MixRequest::Output(o) => {
                out.push(WHAT_OUTPUT);
                put16(&mut out, &o.spk);
                out.extend_from_slice(&o.nf);
                out.extend_from_slice(&digest_to_lane_bytes(&o.leaf_commit));
                out.extend_from_slice(&digest_to_lane_bytes(&o.out1_cm));
                put32(&mut out, &o.burn);
                put32(&mut out, &o.membership);
            }
            MixRequest::Sign { txid, vout, sig } => {
                out.push(WHAT_SIGN);
                out.extend_from_slice(txid);
                out.extend_from_slice(&vout.to_le_bytes());
                out.extend_from_slice(sig);
            }
        }
        out
    }

    /// `None` for anything but one exact, bounded request.
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<([u8; 32], MixRequest)> {
        let mut r = Rd { b, i: 0 };
        if r.u8()? != BULK_REQ_KIND_MIX {
            return None;
        }
        let round = r.a32()?;
        let req = match r.u8()? {
            WHAT_INPUT => {
                let txid = r.a32()?;
                let vout = r.u32()?;
                let n = r.u8()? as usize;
                if n == 0 || n > CREDS_PER_INPUT_MAX {
                    return None;
                }
                let openings = (0..n).map(|_| r.digest()).collect::<Option<Vec<_>>>()?;
                let change_spk = r.bytes16(P2TR_SPK_BYTES)?.to_vec();
                let own_sig: [u8; 64] = r.take(64)?.try_into().ok()?;
                MixRequest::Input(InputReg { txid, vout, openings, change_spk, own_sig })
            }
            WHAT_OUTPUT => {
                let spk = r.bytes16(P2TR_SPK_BYTES)?.to_vec();
                let nf = r.a32()?;
                let leaf_commit = r.digest()?;
                let out1_cm = r.digest()?;
                let burn = r.bytes32(MIX_PROOF_MAX)?.to_vec();
                let membership = r.bytes32(MIX_PROOF_MAX)?.to_vec();
                MixRequest::Output(OutputReg { spk, nf, leaf_commit, out1_cm, burn, membership })
            }
            WHAT_SIGN => {
                let txid = r.a32()?;
                let vout = r.u32()?;
                let sig: [u8; 64] = r.take(64)?.try_into().ok()?;
                MixRequest::Sign { txid, vout, sig }
            }
            _ => return None,
        };
        r.done().then_some((round, req))
    }
}

/// The answer page for a request: `MIXANS ‖ H(request) ‖ ok ‖ reason`.
#[must_use]
pub fn answer_page(request: &[u8], verdict: Result<(), &str>) -> Vec<u8> {
    let mut out = MIX_ANSWER_TAG.to_vec();
    out.extend_from_slice(blake3::hash(request).as_bytes());
    match verdict {
        Ok(()) => out.push(1),
        Err(why) => {
            out.push(0);
            let b = why.as_bytes();
            out.extend_from_slice(&b[..b.len().min(MIX_REASON_MAX)]);
        }
    }
    out
}

/// `(H(request), Ok | Err(reason))` from an answer page.
#[must_use]
pub fn parse_answer(page: &[u8]) -> Option<([u8; 32], Result<(), String>)> {
    let rest = page.strip_prefix(MIX_ANSWER_TAG.as_slice())?;
    if rest.len() < 33 || rest.len() > 33 + MIX_REASON_MAX {
        return None;
    }
    let h: [u8; 32] = rest[..32].try_into().ok()?;
    match rest[32] {
        1 if rest.len() == 33 => Some((h, Ok(()))),
        0 => Some((h, Err(String::from_utf8_lossy(&rest[33..]).into_owned()))),
        _ => None,
    }
}

/// ⭐ THE ROUND'S PUBLIC STATE as every node relays it: the terms, the coordinator's onion address (where registrations
/// go), the phase and its end on the epoch clock, the signed record once inputs close, the unsigned transaction once
/// outputs close (with each input's value and script, what BIP 341 signs) — all under the coordinator's ML-DSA signature.
/// A view is accepted only from the epoch's designated coordinator (a bonded custodian), so nobody else can open rounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundView {
    pub terms: RoundTerms,
    pub epoch: u64,
    pub coordinator_addr: String,
    pub phase: Phase,
    pub record: Option<(Vec<Digest4>, Digest4, Vec<u8>)>,
    pub tx: Option<Payout>,
    pub sig: Vec<u8>,
}

fn phase_byte(p: Phase) -> u8 {
    match p {
        Phase::Inputs => 0,
        Phase::Outputs => 1,
        Phase::Signing => 2,
        Phase::Broadcast => 3,
    }
}

impl RoundView {
    fn body(&self) -> Vec<u8> {
        let mut out = b"MUSD/entry-mix/view/v1".to_vec();
        out.extend_from_slice(&self.terms.round_id);
        out.extend_from_slice(&self.terms.denom.to_le_bytes());
        out.extend_from_slice(&self.terms.fee_rate_sat_vb.to_le_bytes());
        put16(&mut out, &self.terms.coordinator_pk);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        put16(&mut out, self.coordinator_addr.as_bytes());
        out.push(phase_byte(self.phase));
        match &self.record {
            None => out.push(0),
            Some((leaves, root, sig)) => {
                out.push(1);
                out.extend_from_slice(&(leaves.len() as u16).to_le_bytes());
                for l in leaves {
                    out.extend_from_slice(&digest_to_lane_bytes(l));
                }
                out.extend_from_slice(&digest_to_lane_bytes(root));
                put16(&mut out, sig);
            }
        }
        match &self.tx {
            None => out.push(0),
            Some(tx) => {
                out.push(1);
                out.extend_from_slice(&(tx.inputs.len() as u16).to_le_bytes());
                for i in &tx.inputs {
                    out.extend_from_slice(&i.txid);
                    out.extend_from_slice(&i.vout.to_le_bytes());
                    out.extend_from_slice(&i.value_sats.to_le_bytes());
                    put16(&mut out, &i.script_pubkey);
                    out.extend_from_slice(&i.sequence.to_le_bytes());
                }
                out.extend_from_slice(&(tx.outputs.len() as u16).to_le_bytes());
                for o in &tx.outputs {
                    out.extend_from_slice(&o.value_sats.to_le_bytes());
                    put16(&mut out, &o.script_pubkey);
                }
            }
        }
        out
    }

    /// Sign the view with the coordinator's key.
    #[must_use]
    pub fn signed(mut self, sk: &[u8]) -> Option<RoundView> {
        self.sig = crate::pqauth::ml_dsa_sign(&self.body(), sk)?;
        Some(self)
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.body();
        put16(&mut out, &self.sig);
        out
    }

    /// Decode and verify a relayed view: exact length, every width bounded, the coordinator's signature over it, the
    /// record (when present) signed for this round and refolding to its root. Whether the signer is the epoch's
    /// designated custodian is the caller's check (it holds the custodian set).
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<RoundView> {
        let mut r = Rd { b, i: 0 };
        if r.take(22)? != b"MUSD/entry-mix/view/v1" {
            return None;
        }
        let round_id = r.a32()?;
        let denom = r.u64()?;
        let fee_rate_sat_vb = r.u64()?;
        let coordinator_pk = r.bytes16(4096)?.to_vec();
        let epoch = r.u64()?;
        let coordinator_addr = String::from_utf8(r.bytes16(MIX_ADDR_MAX)?.to_vec()).ok()?;
        let phase = match r.u8()? {
            0 => Phase::Inputs,
            1 => Phase::Outputs,
            2 => Phase::Signing,
            3 => Phase::Broadcast,
            _ => return None,
        };
        let record = match r.u8()? {
            0 => None,
            1 => {
                let n = r.u16()? as usize;
                if n > ROUND_LEAVES {
                    return None;
                }
                let leaves = (0..n).map(|_| r.digest()).collect::<Option<Vec<_>>>()?;
                let root = r.digest()?;
                let sig = r.bytes16(8192)?.to_vec();
                Some((leaves, root, sig))
            }
            _ => return None,
        };
        let tx = match r.u8()? {
            0 => None,
            1 => {
                let ni = r.u16()? as usize;
                if ni > ROUND_LEAVES {
                    return None;
                }
                let mut inputs = Vec::with_capacity(ni);
                for _ in 0..ni {
                    let txid = r.a32()?;
                    let vout = r.u32()?;
                    let value_sats = r.u64()?;
                    let script_pubkey = r.bytes16(P2TR_SPK_BYTES)?.to_vec();
                    let sequence = r.u32()?;
                    inputs.push(TxIn { txid, vout, value_sats, script_pubkey, sequence });
                }
                let no = r.u16()? as usize;
                if no > 2 * ROUND_LEAVES {
                    return None;
                }
                let mut outputs = Vec::with_capacity(no);
                for _ in 0..no {
                    let value_sats = r.u64()?;
                    let script_pubkey = r.bytes16(P2TR_SPK_BYTES)?.to_vec();
                    outputs.push(TxOut { value_sats, script_pubkey });
                }
                Some(Payout { inputs, outputs })
            }
            _ => return None,
        };
        let sig = r.bytes16(8192)?.to_vec();
        if !r.done() {
            return None;
        }
        let v = RoundView { terms: RoundTerms { round_id, denom, fee_rate_sat_vb, coordinator_pk }, epoch, coordinator_addr, phase, record, tx, sig };
        if !crate::pqauth::ml_dsa_verify(&v.body(), &v.terms.coordinator_pk, &v.sig) {
            return None;
        }
        if let Some((leaves, root, rsig)) = &v.record {
            if record_root(leaves) != *root || !crate::pqauth::ml_dsa_verify(&record_msg(&v.terms.round_id, root, leaves.len()), &v.terms.coordinator_pk, rsig) {
                return None;
            }
        }
        Some(v)
    }
}

impl Round {
    /// The round's signed public view for `epoch` at `addr`.
    #[must_use]
    pub fn view(&self, epoch: u64, addr: &str) -> Option<RoundView> {
        let tx = matches!(self.phase, Phase::Signing | Phase::Broadcast).then(|| self.unsigned_tx().ok()).flatten();
        RoundView { terms: self.terms.clone(), epoch, coordinator_addr: addr.to_string(), phase: self.phase, record: self.record(), tx, sig: Vec::new() }.signed(&self.sk)
    }

    /// Dispatch one decoded request to its door.
    pub fn handle(&mut self, req: MixRequest, prevout: PrevoutLookup) -> Result<(), &'static str> {
        match req {
            MixRequest::Input(r) => self.register_input(r, prevout),
            MixRequest::Output(o) => self.register_output(o),
            MixRequest::Sign { txid, vout, sig } => self.add_signature(&txid, vout, sig),
        }
    }

    /// The round's inputs count (for the census line and the close rule).
    #[must_use]
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
}

#[cfg(test)]
mod tests {
    //! The §BR-6 refuters (spec §3), RED first: every tamper below is refused, and the honest round moves real coins on
    //! the simulated Bitcoin (Core regtest semantics, `btc_sim`). TWO-PARTY-REVIEWED: the coordinator and the users are
    //! separate state here (the coordinator holds only what the wire carries it); the cross-node half is B6-c's netsim step.
    use super::*;
    use crate::btc_sim::SimBitcoin;

    struct User {
        secret: [u8; 32],
        coin: ([u8; 32], u32, u64),
        cred: Credential,
        out_spk: Vec<u8>,
        change_spk: Vec<u8>,
    }

    fn vault(tag: &str, i: usize) -> ([u8; 32], Vec<u8>) {
        let seed: [u8; 32] = *blake3::hash(format!("entry-mix-test/{tag}/{i}").as_bytes()).as_bytes();
        let (x, dq) = btc_tx::vault_single_key_output(&seed).expect("a hash is a key"); // CLASSICAL-CRYPTO-EXEMPT: a test vault on Bitcoin's own curve (bridge endpoint)
        (dq, btc_tx::p2tr_script_pubkey(&x))
    }

    fn lookup(sim: &SimBitcoin) -> impl Fn(&[u8; 32], u32) -> Option<(u64, Vec<u8>, u64)> + '_ {
        move |txid, vout| {
            let d = btc_tx::txid_display_hex(txid);
            let (v, spk) = sim.tx_out(&d, vout)?;
            Some((v, spk, sim.tx_confirmations(&d).unwrap_or(0)))
        }
    }

    /// `n` users, each with one confirmed vault coin of `coin_sats`, one credential, a fresh output and a change address.
    fn users(sim: &mut SimBitcoin, n: usize, coin_sats: u64) -> Vec<User> {
        (0..n)
            .map(|i| {
                let (secret, spk) = vault("coin", i);
                let x: [u8; 32] = spk[2..34].try_into().unwrap();
                let txid = sim.fund(&btc_tx::reserve_address("bcrt", &x), coin_sats).expect("funded");
                sim.mine(1);
                let (_, out_spk) = vault("out", i);
                let (_, change_spk) = vault("change", i);
                User { secret, coin: (txid, 0, coin_sats), cred: Credential::fresh().expect("entropy"), out_spk, change_spk }
            })
            .collect()
    }

    fn coordinator(denom: u64) -> Round {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let nonce: [u8; 32] = crate::cashout_ticket::fresh_entropy(32).unwrap().try_into().unwrap();
        Round::open(RoundTerms::new(pk, denom, 2, &nonce).expect("a ladder unit"), sk)
    }

    fn register_all(round: &mut Round, sim: &SimBitcoin, us: &[User]) {
        let look = lookup(sim);
        for u in us {
            let reg = sign_input_registration(&round.terms, &u.coin.0, u.coin.1, std::slice::from_ref(&u.cred), &u.change_spk, &u.secret).unwrap();
            round.register_input(reg, &look).expect("an honest input registers");
        }
    }

    #[test]
    fn the_record_tree_refolds_every_leaf_to_its_root_as_the_membership_circuit_reads_it() {
        let leaves: Vec<Digest4> = (0..37u64).map(|i| crate::spend_frontier::cm_bytes_to_leaf(blake3::hash(&i.to_le_bytes()).as_bytes())).collect();
        let root = record_root(&leaves);
        for i in [0usize, 1, 17, 36] {
            let (sib, dirs) = record_copath(&leaves, i).unwrap();
            assert_eq!(sib.len(), ROUND_DEPTH);
            assert_eq!(usdm_decider::note_membership_air::refold_in_block(leaves[i], &sib, &dirs), root, "leaf {i}");
        }
        assert!(record_copath(&leaves, 37).is_none(), "a padding slot is no credential");
        let mut other = leaves.clone();
        other[5] = other[6];
        assert_ne!(record_root(&other), root);
    }

    #[test]
    fn an_input_draws_only_what_its_coin_pays_for_and_only_its_owner_can_register_it() {
        let mut sim = SimBitcoin::new(61);
        let denom = 100_000;
        let us = users(&mut sim, 2, 2 * denom + 50_000);
        let mut round = coordinator(denom);
        let look = lookup(&sim);
        let t = round.terms.clone();
        // another key's signature over the same registration: refused
        let (wrong, _) = vault("coin", 1);
        let forged = sign_input_registration(&t, &us[0].coin.0, 0, std::slice::from_ref(&us[0].cred), &us[0].change_spk, &wrong).unwrap();
        assert!(round.register_input(forged, &look).is_err(), "only the coin's key registers it");
        // a registration signed for another round: refused
        let other = RoundTerms::new(t.coordinator_pk.clone(), denom, 2, &[9u8; 32]).unwrap();
        let replayed = sign_input_registration(&other, &us[0].coin.0, 0, std::slice::from_ref(&us[0].cred), &us[0].change_spk, &us[0].secret).unwrap();
        assert!(round.register_input(replayed, &look).is_err(), "a registration is bound to its round");
        // a swapped credential opening after signing: refused
        let mut swapped = sign_input_registration(&t, &us[0].coin.0, 0, std::slice::from_ref(&us[0].cred), &us[0].change_spk, &us[0].secret).unwrap();
        swapped.openings[0] = Credential::fresh().unwrap().opening();
        assert!(round.register_input(swapped, &look).is_err(), "the signature covers every opening");
        // more credentials than the coin pays for: refused
        let three: Vec<Credential> = (0..3).map(|_| Credential::fresh().unwrap()).collect();
        let greedy = sign_input_registration(&t, &us[0].coin.0, 0, &three, &us[0].change_spk, &us[0].secret).unwrap();
        assert!(round.register_input(greedy, &look).is_err(), "3 units from a coin of 2.5");
        // the honest registration, then the same coin again, then a reused opening on another coin
        let two: Vec<Credential> = (0..2).map(|_| Credential::fresh().unwrap()).collect();
        let ok = sign_input_registration(&t, &us[0].coin.0, 0, &two, &us[0].change_spk, &us[0].secret).unwrap();
        round.register_input(ok.clone(), &look).expect("two units from a coin of 2.5");
        assert!(round.register_input(ok, &look).is_err(), "one registration per coin");
        let reuse = sign_input_registration(&t, &us[1].coin.0, 0, std::slice::from_ref(&two[0]), &us[1].change_spk, &us[1].secret).unwrap();
        assert!(round.register_input(reuse, &look).is_err(), "a credential opening is never issued twice");
        // the change the input door computed: 2.5 units − 2 units − the input's own fee
        assert_eq!(t.change_for(2 * denom + 50_000, 2).unwrap(), Some(50_000 - t.input_fee(2, true)));
        // too few inputs: the round does not close
        assert!(round.close_inputs().is_err(), "one input is no mix");
    }

    #[test]
    fn a_coordinator_that_signs_two_records_for_one_round_is_caught_by_any_two_users() {
        let round = coordinator(100_000);
        let a = vec![crate::spend_frontier::cm_bytes_to_leaf(&[1u8; 32])];
        let b = vec![crate::spend_frontier::cm_bytes_to_leaf(&[2u8; 32])];
        let (ra, rb) = (record_root(&a), record_root(&b));
        let sa = crate::pqauth::ml_dsa_sign(&record_msg(&round.terms.round_id, &ra, 1), &round.sk).unwrap();
        let sb = crate::pqauth::ml_dsa_sign(&record_msg(&round.terms.round_id, &rb, 1), &round.sk).unwrap();
        assert!(is_equivocation(&round.terms, (&ra, 1, &sa), (&rb, 1, &sb)), "two signed roots for one round is a fault");
        assert!(!is_equivocation(&round.terms, (&ra, 1, &sa), (&ra, 1, &sa)), "one root served twice is not");
        assert!(!is_equivocation(&round.terms, (&ra, 1, &sa), (&rb, 1, &sa)), "a signature that does not verify proves nothing");
    }

    /// ⭐⭐⭐ THE ROUND, END TO END, WITH REFUTERS 1–4 INLINE: four users mix one ladder unit each on the simulated Bitcoin;
    /// a credential redeemed twice, a burn moved to another script, a credential from another record and a transaction
    /// missing a user's output are each refused; the honest transaction confirms and pays every output exactly a unit.
    #[test]
    fn br6_four_users_mix_a_ladder_unit_each_and_every_refuter_is_refused() {
        let mut sim = SimBitcoin::new(62);
        let denom = 100_000;
        let us = users(&mut sim, 4, denom + 40_000);
        let mut round = coordinator(denom);
        register_all(&mut round, &sim, &us);
        let (leaves, root, sig) = round.close_inputs().expect("four inputs close the round");
        let t = round.terms.clone();
        for u in &us {
            assert!(check_record(&t, &leaves, &root, &sig, &u.cred).is_some(), "every user finds its credential in the signed record");
        }
        // user 0 redeems honestly
        let o0 = prove_output(&t, &leaves, &us[0].cred, &us[0].out_spk).expect("the burn proves");
        round.register_output(o0).expect("an honest output registers");
        // REFUTER 1: the same credential again (a fresh proof, another script) — one nullifier, one output
        let (_, again_spk) = vault("again", 0);
        let o0b = prove_output(&t, &leaves, &us[0].cred, &again_spk).unwrap();
        assert_eq!(round.register_output(o0b).unwrap_err(), "this credential is already redeemed");
        // REFUTER 3: user 1's burn bound to its script, registered for another script
        let mut o1 = prove_output(&t, &leaves, &us[1].cred, &us[1].out_spk).unwrap();
        let honest_spk = std::mem::replace(&mut o1.spk, again_spk.clone());
        assert_eq!(round.register_output(o1.clone()).unwrap_err(), "the burn does not prove one ladder unit to this output");
        o1.spk = honest_spk;
        round.register_output(o1).expect("the same burn registers for the script it was proven for");
        // REFUTER 2: a credential the round never issued, proven against a record that holds it (another round's record)
        let forged = Credential::fresh().unwrap();
        let mut fake_leaves = leaves.clone();
        fake_leaves[2] = forged.cm(&t);
        let o_forged = prove_output(&t, &fake_leaves, &forged, &again_spk).expect("it proves against its own record");
        assert_eq!(round.register_output(o_forged).unwrap_err(), "the credential is not a member of this round's record");
        assert!(prove_output(&t, &leaves, &forged, &again_spk).is_none(), "and no proof against the signed record exists");
        for u in &us[2..] {
            round.register_output(prove_output(&t, &leaves, &u.cred, &u.out_spk).unwrap()).expect("an honest output registers");
        }
        let tx = round.close_outputs().expect("the transaction");
        // REFUTER 4a: a transaction missing (or redirecting) a user's output gets no signature from that user
        fn change_of<'a>(t: &RoundTerms, u: &'a User) -> Option<(&'a [u8], u64)> {
            t.change_for(u.coin.2, 1).unwrap().map(|c| (u.change_spk.as_slice(), c))
        }
        let mut cheat = tx.clone();
        let at = cheat.outputs.iter().position(|o| o.script_pubkey == us[3].out_spk).unwrap();
        cheat.outputs[at].script_pubkey = again_spk.clone();
        assert!(may_sign(&t, &cheat, (&us[3].coin.0, 0, us[3].coin.2), std::slice::from_ref(&us[3].out_spk), change_of(&t, &us[3])).is_none(), "a redirected output is not signed for");
        let mut short = tx.clone();
        short.outputs[at].value_sats -= 1;
        assert!(may_sign(&t, &short, (&us[3].coin.0, 0, us[3].coin.2), std::slice::from_ref(&us[3].out_spk), change_of(&t, &us[3])).is_none(), "an output one sat short is not signed for");
        // every output of the honest transaction is one unit or an input's exact change
        assert_eq!(tx.outputs.iter().filter(|o| o.value_sats == denom).count(), 4);
        // REFUTER 4b: three of four sign — the round finalizes nothing, and the blame round admits only the signers
        for u in &us[..3] {
            let idx = may_sign(&t, &tx, (&u.coin.0, 0, u.coin.2), std::slice::from_ref(&u.out_spk), change_of(&t, u)).expect("the user's outputs are present");
            round.add_signature(&u.coin.0, 0, sign_round_input(&tx, idx, &u.secret).unwrap()).expect("a valid signature");
        }
        let (wrong, _) = vault("coin", 1);
        let idx3 = may_sign(&t, &tx, (&us[3].coin.0, 0, us[3].coin.2), std::slice::from_ref(&us[3].out_spk), change_of(&t, &us[3])).unwrap();
        assert!(round.add_signature(&us[3].coin.0, 0, sign_round_input(&tx, idx3, &wrong).unwrap()).is_err(), "another key's signature is refused");
        let missing = round.finalize().unwrap_err();
        assert_eq!(missing, vec![(us[3].coin.0, 0)], "the round names the coin that did not sign");
        let blame = round.blame_round(&[7u8; 32]).unwrap();
        assert_eq!(blame.allowed.as_ref().unwrap().len(), 3, "the blame round admits the three signers only");
        // the fourth signs: the transaction confirms on Bitcoin and pays every output exactly a unit
        round.add_signature(&us[3].coin.0, 0, sign_round_input(&tx, idx3, &us[3].secret).unwrap()).expect("a valid signature");
        let raw = round.finalize().expect("every coin signed");
        let txid = sim.broadcast(&btc_tx::hex(&raw)).expect("Bitcoin admits the round's transaction");
        sim.mine(1);
        assert_eq!(sim.tx_confirmations(&txid), Some(1));
        for u in &us {
            let x: [u8; 32] = u.out_spk[2..34].try_into().unwrap();
            assert_eq!(sim.received_sats(&btc_tx::reserve_address("bcrt", &x)), denom, "the output holds exactly one ladder unit");
        }
        eprintln!("[measure] br6 round: {} inputs, {} outputs, {} raw bytes", tx.inputs.len(), tx.outputs.len(), raw.len());
    }

    /// ⭐⭐ REFUTER 5 — THE LINKABILITY CENSUS over the coordinator's full view: every input registration and every output
    /// registration. For each output the coordinator runs every test it can evaluate against each candidate input's
    /// credential — the membership proof against a record holding only that credential, against the record with that
    /// credential removed, the nullifier and leaf commitment recomputed under every value it holds — and no test singles
    /// out the input behind the output: each output stays consistent with all n inputs (a guess is 1/n).
    #[test]
    fn a_coordinator_holding_every_registration_cannot_single_out_the_input_behind_an_output() {
        let mut sim = SimBitcoin::new(63);
        let denom = 100_000;
        let us = users(&mut sim, 4, denom + 40_000);
        let mut round = coordinator(denom);
        register_all(&mut round, &sim, &us);
        let (leaves, root, _) = round.close_inputs().unwrap();
        let t = round.terms.clone();
        let regs: Vec<OutputReg> = us.iter().map(|u| prove_output(&t, &leaves, &u.cred, &u.out_spk).unwrap()).collect();
        let held: Vec<Digest4> = leaves.clone();
        let mut singled_out = 0usize;
        for o in &regs {
            let nf = cm_bytes_to_root(&o.nf).unwrap();
            let mut consistent = 0usize;
            for (i, cm) in held.iter().enumerate() {
                let mut only = vec![usdm_decider::poseidon2_compress::ZERO_DIGEST; leaves.len()];
                only[i] = *cm;
                let mut without = leaves.clone();
                without[i] = usdm_decider::poseidon2_compress::ZERO_DIGEST;
                let tests = [
                    usdm_decider::note_membership_air::verify_note_membership_one_step(&o.membership, o.leaf_commit, nf, record_root(&only)),
                    usdm_decider::note_membership_air::verify_note_membership_one_step(&o.membership, o.leaf_commit, nf, record_root(&without)),
                    // every digest the coordinator holds tried as the blind and as the nullifier key
                    held.iter().chain([root, nf].iter()).any(|g| usdm_decider::note_membership_air::note_leaf_commitment(*cm, nf, *g) == o.leaf_commit),
                    held.iter().chain([root].iter()).any(|g| usdm_decider::whir_rec_block::note_nullifier(g, cm) == nf),
                ];
                // a test is informative only if it answers differently for the true input than for the others
                if tests.iter().all(|r| !r) {
                    consistent += 1;
                }
            }
            if consistent < held.len() {
                singled_out += 1;
            }
            assert!(usdm_decider::note_membership_air::verify_note_membership_one_step(&o.membership, o.leaf_commit, nf, root), "and it verifies against the real record");
        }
        eprintln!("[measure] br6 census: {} outputs, {} singled out of {} candidates each", regs.len(), singled_out, held.len());
        assert_eq!(singled_out, 0, "no output is narrowed below the round's full anonymity set");
    }
}
