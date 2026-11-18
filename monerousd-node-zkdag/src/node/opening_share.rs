// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — ⭐⭐ A-F19 (lane dcash, 2026-11-10): A CUSTODIAN'S HIDDEN OPENING IS RECOVERED FROM ANY PEER, AND IS TAKEN
//! ONLY IF IT OPENS THE CHAIN'S OWN COMMITMENT.
//!
//! FOUND (speed / vaults, read from the code on main 64469a7a, findings row A-F19): a stability-pool object is executed by ONE
//! custodian, which seals the pool's step `(amount, blind)` to every bonded custodian (`execute_pool_deposit`, `_withdraw`). The door
//! verifies the object's proofs but cannot open an envelope, so an executor that seals garbage to the others leaves each of them an
//! opening that no longer opens the pool's words (`advance_pool_opening_from_deposit`: "opening unchanged"), and nothing ever
//! recovered it: that custodian could not again prove a pool deposit, withdrawal, liquidation or payout for the asset. The same holds
//! for every hidden opening custody keeps from one executor's sealed leg — the reserve and minted pair of each PSM (a mint, a burn, a
//! cash-out leg) and the stakers' pool paid-out total (`[stake] … opening unchanged`) — and for a custodian that restarted from an
//! older opening file, or bonded after the custody state moved.
//!
//! THE RULE, BORROWED (Feldman / Pedersen verifiable secret sharing: a share is accepted only if it verifies against the public
//! commitment). Each of these openings is checkable against commitments the chain itself holds: a pool's `PoolOpening::words`
//! against `PegLedger::pool_words`; a PSM's `(reserve, minted)` pair against `PegLedger::commits_of_opening` of the chain's reserve and
//! minted commitments; the stakers' paid-out pair against `stake_paid_commit`. So a custodian whose opening does not open them ASKS,
//! naming a digest of the commitments its chain holds; any bonded custodian whose opening opens exactly those GIVES it, sealed to the
//! asker's registered custody ML-KEM key; the asker installs it only if it reproduces the chain's commitments, through each opening's
//! ONE writer (`set_custodian_opening_seal`, `set_wrapped_opening_seal`, `set_custodian_paid_seal`, the pool map + its persist). No
//! party is trusted: a wrong answer is refused by the check, a missing one is answered by any other custodian.
//!
//! §9.6 (a new ingress path): (1) proof of work — n/a: a peer message, not a chain object, and it moves no chain state. (2) the
//! object's own proof — the opening is checked against the chain's commitments, the one thing that makes an opening usable. (3) value
//! — it creates none: an opening is a private view of commitments the chain already holds; a wrong one is refused, a right one changes
//! no word. (4) replay — a give for commitments the chain no longer holds fails the same check; an ask for others is not answered.
//! (5) work bound — an answer is sealed only to a BONDED custodian's REGISTERED key, at most once per (asker, opening) per
//! [`GIVE_EVERY_MS`]; an ask leaves only for an opening that is stale here, once per opening per [`ASK_EVERY_MS`]; each message is
//! relayed once (the runtime's seen set). (6) parity with the door it parallels — each opening's sealed leg in its object is installed
//! by the same commitment check through the same writer; this path adds no install the leg path lacks.
//! SAFE AT SCALE (§9.6 question 7): an ask is one small message per stranded custodian per stale opening; a give is one envelope per
//! answer; nothing is signed by, or carried once per, every bonded node.
//! AI RESISTANT (§9.6 question 8): protected by (a), a check every taker makes against public state — an opening is installed only
//! if it opens the chain's own commitments, so a lying peer needs a second opening of one Poseidon2 commitment, which is the
//! commitment's binding, not a review or a person. A lying prover gains nothing (its give is refused, and the taker keeps asking); a
//! persuasive message gains nothing (no person is in the loop, and the asker accepts no claim about the chain, only bytes that
//! reproduce it). Withholding costs only time: any other custodian answers.
//!
//! DIGITAL CASH: an ask names a custodian (the bonded set is public), an opening kind, a public asset id and a digest of commitments
//! every node holds; a give is sealed to one custodian's key. The custody totals inside are what every bonded custodian already holds;
//! no user, note, amount, address or owner is on the wire.

use super::*;

/// A PSM's stability pool (`PoolOpening`), keyed by asset id.
pub const KIND_POOL: u8 = 1;
/// A PSM's reserve and minted pair `(reserve, reserve_blind, minted, minted_blind)`, keyed by asset id (the native peg or a wrapped asset).
pub const KIND_RESERVE: u8 = 2;
/// The stakers' pool paid-out total `(paid, blind)`, key 0.
pub const KIND_STAKERS_PAID: u8 = 3;
/// ⭐ SAFE AT SCALE (lane vaults, 2026-11-11) — the reserve pair of a RETIRING vault's ledger, keyed by that ledger's id, for
/// the merge now due on the chain (`Class::VaultMerge`): asked by a custodian of the vault the chain's own rule names as
/// receiving (it must open both vaults' ledgers to prove the merge's sums), answered only by a custodian of the retiring
/// vault, and kept in the asker's merge slot only if it opens the pair the asker's own chain holds for that ledger.
pub const KIND_MERGE: u8 = 4;
/// ⭐ SAFE AT SCALE, stage three (spec §3g.1) — the PART at rest in a giving vault's slot and that vault's opening as the carve
/// left it, keyed by the giving vault's ledger id of that kind: asked by a custodian of the vault the slot is FOR, answered only
/// by a custodian of the giving vault, and kept (`Node::REBALANCE_IN`) only when both open the commitments the asker's own
/// chain holds in the slot AND the part is exactly the eighth of both words of the giver's ledger as it stood
/// (`PegLedger::parts_are_one_fraction`): the receiving vault never consents to a part that sheds USDm and keeps its coins.
pub const KIND_PART: u8 = 5;
/// A stranded custodian asks again at most this often per opening.
pub const ASK_EVERY_MS: u64 = 30_000;
/// A custodian answers one asker for one opening at most this often.
pub const GIVE_EVERY_MS: u64 = 30_000;
/// The sealed body's bound: every opening above is under 200 bytes in postcard; anything wider is refused before any work.
const BODY_MAX: usize = 256;
const TAG_BYTES: usize = 16;

/// The custody hand-over lanes, by the tag their signed statement names: an envelope of one lane never verifies as
/// another's. `WireMsg::OpeningShare`, `WireMsg::CoinShare`, `WireMsg::LegShare`.
pub const LANE_OPENING: u8 = 1;
pub const LANE_COIN: u8 = 2;
pub const LANE_LEG: u8 = 3;
/// The widest hand-over message of each lane (the message's own encoding, before the envelope): an opening ask or its
/// sealed answer; a coin-list ask or one sealed chunk; a leg ask or one cash-out's signed parts.
pub const SHARE_BODY_MAX_OPENING: usize = 2_048;
pub const SHARE_BODY_MAX_COIN: usize = crate::btc_payout::COIN_SHARE_BODY_MAX + 2_048;
pub const SHARE_BODY_MAX_LEG: usize = crate::btc_payout::LEG_SHARE_PROOF_MAX + 256;
/// The hand-over messages one bonded custodian has relayed for it per window, all three lanes together: its asks (a
/// few openings, one coin list, `LEG_WANT_MAX` legs) and as many answers again.
pub const SHARE_WINDOW_MS: u64 = 10_000;
pub const SHARE_PER_SIGNER: u32 = 64;

/// ⭐ A-F30 (lane vaults, 2026-11-11) — A CUSTODY HAND-OVER MESSAGE AS IT TRAVELS: the lane's own message, and the bonded
/// custodian that sent it with its ML-DSA signature.
///
/// WHAT WAS OPEN: the opening lane (A-F19) and the coin-list lane relayed "every message once", whoever made it. An ask
/// names a bonded custodian, but nobody signed it, so any peer could make every node relay an unbounded stream of
/// distinct asks and sealed answers on the custody gossip class — a flood beside the signature and proposal lanes that
/// share the class (no value moved and nothing unsigned was believed; the cost was the mesh's bytes). The leg lane's
/// answer is a cash-out's signed parts, about 80 KB, so the class could not stay open.
///
/// §9.6 for the RELAY (a peer door every node runs — [`NodeRuntime`]'s three hand-over arms call this and nothing else
/// before they read a message): (1) no PoW — the sender's cost is its bond; (2) only a message signed by a custodian
/// that holds custody weight on THIS node's chain is processed or relayed ([`Node::share_signer`]), and an ask's `from`
/// must be that signer (each lane checks its own message); (3) no value; (4) a repeat is dropped by the relay-once
/// ring; (5) one signature verify per message from a bonded key (a stranger's costs a set lookup), at most
/// `SHARE_PER_SIGNER` messages per signer per `SHARE_WINDOW_MS` ([`ShareRelayBound`]), each bounded at the decode;
/// (6) parity with the signature lanes (`VaultKeySig`, `LiquidationSig`: gathered against the node's own bonded set,
/// re-gossiped only when valid) — the hand-over lanes now meet it; (7) SAFE AT SCALE: one signature (about 3.3 KB)
/// per hand-over message; the bound holds one counter per signer seen in the current window, cleared with it — a
/// vault's custodians in practice, the bonded set at most; nothing per height; (8) AI RESISTANT: (b) code and
/// economics — a signature under a bonded key and a count; a lying sender gains nothing each lane's own check did not
/// already refuse, and a persuasive message gains nothing: only signed bytes are read.
/// BORROWED: Bitcoin's `addr` relay (rate-limited per peer since 22.0, after the same unbounded-relay finding) and
/// this tree's vote lane (a statement is relayed only under a bonded signature).
/// cons: 3.3 KB and one ML-DSA verify per hand-over message at every node that relays it; a custodian whose
/// validator key is not loaded (a watch-only node) can neither ask nor answer.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedShare {
    pub lane: u8,
    /// O1-FOOTPRINT-REVIEWED: bounded by the lane's `SHARE_BODY_MAX_*` (`decode` refuses wider).
    pub body: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `PEG_ATTEST_PUBKEY_MAX` / `PEG_ATTEST_SIG_MAX` (`decode` refuses wider).
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

impl SignedShare {
    /// What the sender signs: the hand-over domain, the lane and the message's one encoding.
    #[must_use]
    pub fn statement(lane: u8, body: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(40 + body.len());
        m.extend_from_slice(&crate::pqauth::node_statement(b"musdm.custody.share.v1"));
        m.push(lane);
        m.extend_from_slice(&(body.len() as u64).to_le_bytes());
        m.extend_from_slice(body);
        m
    }
    #[must_use]
    pub fn sign(lane: u8, body: Vec<u8>, pk: &[u8], sk: &[u8]) -> Option<Self> {
        let sig = crate::pqauth::ml_dsa_sign(&Self::statement(lane, &body), sk)?;
        Some(SignedShare { lane, body, pubkey: pk.to_vec(), sig })
    }
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }
    /// `None` for anything that is not exactly one envelope of `lane` within its bounds.
    #[must_use]
    pub fn decode(bytes: &[u8], lane: u8, body_max: usize) -> Option<Self> {
        let m: Self = crate::chain_object::decode_exact(bytes)?;
        (m.lane == lane
            && !m.body.is_empty()
            && m.body.len() <= body_max
            && m.pubkey.len() <= crate::peg_attest::PEG_ATTEST_PUBKEY_MAX
            && m.sig.len() <= crate::peg_attest::PEG_ATTEST_SIG_MAX)
            .then_some(m)
    }
}

/// The relay's count: how many hand-over messages each signer had relayed here in the window that began at `start_ms`.
/// O1-INFINITY-REVIEWED: one counter per signer seen in the current window (bonded custodians only), cleared when the
/// window ends.
#[derive(Clone, Debug, Default)]
pub struct ShareRelayBound {
    start_ms: u64,
    seen: std::collections::BTreeMap<[u8; 32], u32>,
}

impl ShareRelayBound {
    /// May one more message of `signer` be processed and relayed now?
    pub fn admit(&mut self, signer: [u8; 32], now_ms: u64) -> bool {
        if now_ms.saturating_sub(self.start_ms) >= SHARE_WINDOW_MS {
            self.start_ms = now_ms;
            self.seen.clear();
        }
        let n = self.seen.entry(signer).or_insert(0);
        if *n >= SHARE_PER_SIGNER {
            return false;
        }
        *n += 1;
        true
    }
}

impl Node {
    /// The bonded custodian that signed a hand-over envelope: its key holds custody weight on this node's chain and
    /// its signature verifies over the envelope's lane and body. `None` otherwise — the message is neither read nor
    /// relayed. CACHE-ONLY: a relay decision from the chain-derived validator set; no chain state moves.
    #[must_use]
    pub fn share_signer(&self, m: &SignedShare, verifier: &dyn crate::pqauth::PqVerifier) -> Option<[u8; 32]> {
        let id = crate::pqauth::pubkey_id(&m.pubkey);
        if !self.validators.is_bonded_custodian(&id) {
            return None;
        }
        verifier.verify(&m.pubkey, &SignedShare::statement(m.lane, &m.body), &m.sig).then_some(id)
    }
}

type ReservePair = (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4);
type PaidPair = (u128, crate::spend_frontier::Digest4);


/// One opening-share message (`WireMsg::OpeningShare`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OpeningShare {
    /// The bonded custodian `from` holds no opening of `(kind, key)` that opens `words` (a digest of the commitments its chain
    /// holds now) and asks for one.
    Ask { kind: u8, key: u32, words: [u8; 32], from: [u8; 32] },
    /// An opening of `(kind, key)` at `words`, sealed to the bonded custodian `to`.
    Give { kind: u8, key: u32, words: [u8; 32], to: [u8; 32], sealed: Vec<u8> },
}

impl OpeningShare {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }
    /// `None` for anything that is not exactly one message of this lane within its bounds.
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<Self> {
        let m: Self = crate::chain_object::decode_exact(b)?;
        match &m {
            OpeningShare::Give { sealed, .. } if sealed.len() > crate::pqkem::ciphertext_len() + TAG_BYTES + BODY_MAX => None,
            _ => Some(m),
        }
    }
}

/// The digest an ask and a give name: the opening's kind and key and the commitments it must open, as the chain holds them.
#[must_use]
pub fn target_digest(kind: u8, key: u32, parts: &[crate::spend_frontier::Digest4], epoch: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/opening-share/v1/target");
    h.update(&[kind]);
    h.update(&key.to_le_bytes());
    for d in parts {
        h.update(&crate::spend_frontier::digest_to_lane_bytes(d));
    }
    h.update(&epoch.to_le_bytes());
    *h.finalize().as_bytes()
}

/// The stream key and tag of this lane alone, so an opening envelope is never read as any other envelope these keys open.
fn stream_and_tag(ss: &[u8], ct: &[u8], body: &[u8]) -> (Vec<u8>, [u8; TAG_BYTES]) {
    let key = blake3::derive_key("MUSD/opening-share/v1/stream", ss);
    let mut ks = vec![0u8; body.len()];
    blake3::Hasher::new_keyed(&key).update(ct).finalize_xof().fill(&mut ks);
    let tag_key = blake3::derive_key("MUSD/opening-share/v1/tag", ss);
    let mut tag = [0u8; TAG_BYTES];
    tag.copy_from_slice(&blake3::keyed_hash(&tag_key, body).as_bytes()[..TAG_BYTES]);
    (ks, tag)
}

/// TESTS — this lane's own seal, for a pin that mounts a LYING giver from another module (a well-formed envelope, sealed to
/// the asker's real key, holding an opening that does not open the chain's commitments).
#[cfg(test)]
pub(crate) fn seal_for_test(ek: &[u8], body: &[u8]) -> Option<Vec<u8>> {
    seal(ek, body)
}

/// Seal `body` to the custodian key `ek`: `ct ‖ tag ‖ body ⊕ stream` (the tag is over the sealed body).
fn seal(ek: &[u8], body: &[u8]) -> Option<Vec<u8>> {
    seal_max(ek, body, BODY_MAX)
}

/// [`seal`] with the caller's own body bound (the coin list of a custody vault is wider than an opening).
fn seal_max(ek: &[u8], body: &[u8], max: usize) -> Option<Vec<u8>> {
    if body.len() > max {
        return None;
    }
    let (ss, ct) = crate::pqkem::encapsulate(ek)?;
    let (ks, _) = stream_and_tag(&ss, &ct, body);
    let sealed: Vec<u8> = body.iter().zip(ks.iter()).map(|(b, k)| b ^ k).collect();
    let (_, tag) = stream_and_tag(&ss, &ct, &sealed);
    let mut out = Vec::with_capacity(ct.len() + TAG_BYTES + sealed.len());
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&sealed);
    Some(out)
}

/// Open an envelope with this custodian's decapsulation key; `None` when it is not this custodian's or is malformed.
fn open(dk: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    open_max(dk, blob, BODY_MAX)
}

/// [`open`] with the caller's own body bound.
fn open_max(dk: &[u8], blob: &[u8], max: usize) -> Option<Vec<u8>> {
    let ct_len = crate::pqkem::ciphertext_len();
    if blob.len() < ct_len + TAG_BYTES || blob.len() > ct_len + TAG_BYTES + max {
        return None;
    }
    let (ct, rest) = blob.split_at(ct_len);
    let (tag, sealed) = rest.split_at(TAG_BYTES);
    let ss = crate::pqkem::decapsulate(ct, dk)?;
    let (ks, want) = stream_and_tag(&ss, ct, sealed);
    if want != tag {
        return None;
    }
    Some(sealed.iter().zip(ks.iter()).map(|(b, k)| b ^ k).collect())
}

impl Node {
    /// ⭐ SAFE AT SCALE, stage three — SEAL `body` (at most `max` bytes) TO A CUSTODIAN OF THIS NODE'S OWN VAULT, under
    /// the custody ML-KEM key the chain registers for `to`. `None` unless this node is a bonded custodian and `to` is
    /// another bonded custodian seated in the same vault: a vault's custody data goes to that vault's custodians only.
    /// The envelope is this lane's own (`stream_and_tag`), so it is never read as any other envelope these keys open.
    pub(crate) fn seal_to_vault_custodian(&self, to: &[u8; 32], body: &[u8], max: usize) -> Option<Vec<u8>> {
        let me = self.custodian_id()?;
        let vault = self.vault_here();
        let seats = self.vault_seats_sorted(vault);
        if *to == me || seats.binary_search(to).is_err() || seats.binary_search(&me).is_err() {
            return None;
        }
        let (_, ek) = self.custodian_eks_of_vault(vault).into_iter().find(|(id, _)| id == to)?;
        seal_max(&ek, body, max)
    }

    /// Open an envelope [`Self::seal_to_vault_custodian`] sealed to THIS custodian — `None` off a custody seat, or
    /// for an envelope that is not this custodian's.
    pub(crate) fn open_as_vault_custodian(&self, sealed: &[u8], max: usize) -> Option<Vec<u8>> {
        let (_, dk) = self.bonded_custodian_identity()?;
        open_max(dk, sealed, max)
    }

    /// The chain's commitments an opening of `(kind, key)` must open, as one digest — `None` for a kind or key this chain does not
    /// hold. The ONE definition every ask, answer and take compares.
    fn opening_target(&self, kind: u8, key: u32) -> Option<[u8; 32]> {
        match kind {
            KIND_POOL if self.is_psm(key) => {
                let w = self.peg.pool_words(key);
                Some(target_digest(kind, key, &[w.t, w.p, w.s], w.epoch))
            }
            KIND_RESERVE | KIND_MERGE => {
                let (r, m) = self.reserve_commits_of(key)?;
                Some(target_digest(kind, key, &[r, m], 0))
            }
            KIND_STAKERS_PAID if key == 0 => Some(target_digest(kind, key, &[self.peg.stake_paid_commit()], 0)),
            KIND_PART => {
                let leg = self.part_leg_of(key)?;
                Some(target_digest(kind, key, &[leg.part.0, leg.part.1, leg.from_post.0, leg.from_post.1], 0))
            }
            _ => None,
        }
    }

    /// The slot leg a PART opening's `key` names — the giving vault's ledger of one kind — when that vault has a part at rest
    /// with a leg of that kind.
    fn part_leg_of(&self, key: u32) -> Option<crate::peg::PartLeg> {
        let asset = crate::peg::ledger_asset_checked(key)?;
        let from = crate::peg::ledger_vault(key);
        self.peg.vault_part(from)?.legs.iter().find(|l| l.asset == asset).copied()
    }

    /// The parts a custodian of a RECEIVING vault needs: every leg of the slot that names its vault, whose part it does not hold.
    fn part_asks(&self) -> Vec<u32> {
        let here = self.vault_here();
        self.peg
            .vault_parts_all()
            .filter(|(_, p)| p.into == here)
            .flat_map(|(from, p)| p.legs.iter().map(move |l| (from, *l)))
            .filter(|(_, l)| self.rebalance_held_opening(Node::REBALANCE_IN, l.asset, l.part).is_none())
            .map(|(from, l)| crate::peg::vault_ledger(from, l.asset))
            .collect()
    }

    /// ⭐ SAFE AT SCALE — the custody-funded ASSET whose ledger of THIS custodian's vault `key` is, when it is one: a
    /// custodian's reserve openings are stored by asset and stand on its own vault's pair (`Node::ledger_here`), so the
    /// lane's key for them is that vault's ledger id as the chain names it (the asset's own id in vault 0).
    fn own_vault_asset(&self, key: u32) -> Option<u32> {
        let asset = crate::peg::ledger_asset_checked(key)?;
        (crate::peg::PegLedger::is_custody_funded(asset) && self.ledger_here(asset) == key).then_some(asset)
    }

    /// The retiring vault's ledgers a custodian of the RECEIVING vault needs an opening of, while a merge into its vault is
    /// due on this node's chain: every custody-funded ledger kind the chain keeps for that vault (one it never moved is
    /// opened by its public genesis opening and is never asked for). Empty with no merge due, or off the receiving vault.
    fn merge_asks(&self) -> Vec<u32> {
        let Some((from, into)) = self.vault_merge_due() else { return Vec::new() };
        if self.vault_here() != into {
            return Vec::new();
        }
        crate::peg::CUSTODY_LEDGER_KINDS.iter().filter(|a| self.peg.vault_pair(from, **a).is_some()).map(|a| crate::peg::vault_ledger(from, *a)).collect()
    }

    /// The vault and asset a MERGE opening's `key` names — the retiring vault's ledger — when a merge out of that vault
    /// into THIS custodian's own vault, or out of this custodian's own vault, is due on this node's chain.
    fn merge_key(&self, key: u32) -> Option<(u32, u32)> {
        let asset = crate::peg::ledger_asset_checked(key)?;
        let from = crate::peg::ledger_vault(key);
        let (due_from, due_into) = self.vault_merge_due()?;
        let here = self.vault_here();
        (crate::peg::PegLedger::is_custody_funded(asset) && due_from == from && (here == due_into || here == from)).then_some((from, asset))
    }

    /// The reserve and minted commitments the chain holds for PSM `key` (the native peg, or a registered wrapped asset).
    fn reserve_commits_of(&self, key: u32) -> Option<(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> {
        if key == crate::peg::NATIVE_PEG_ASSET_ID {
            Some((self.peg.reserve_commit(), self.peg.minted_commit()))
        } else {
            self.peg.wrapped_asset_commits(key)
        }
    }

    /// This node's CURRENT opening of `(kind, key)` as bytes — only when it opens the chain's commitments now.
    fn opening_bytes_now(&self, kind: u8, key: u32) -> Option<Vec<u8>> {
        match kind {
            KIND_POOL => postcard::to_stdvec(&self.pool_opening_now(key)?).ok(),
            KIND_RESERVE => {
                // a custody-funded ledger: only THIS custodian's own vault's (its seal is stored by asset; a higher
                // vault's unmoved ledger reads its public genesis opening); another vault's ledger is not this custodian's
                // to hold. A registered wrapped asset: its seal by its own id, as it was.
                let (r, rb, m, mb) = if crate::peg::ledger_asset_checked(key).is_some_and(crate::peg::PegLedger::is_custody_funded) {
                    self.fresh_opening_for_asset(self.own_vault_asset(key)?)?
                } else {
                    unseal_opening(&self.wrapped_opening_seals.get(&key).cloned()?)
                };
                (crate::peg::PegLedger::commits_of_opening(r, rb, m, mb) == self.reserve_commits_of(key)?)
                    .then(|| postcard::to_stdvec::<ReservePair>(&(r, rb, m, mb)).ok())
                    .flatten()
            }
            KIND_MERGE => {
                // the retiring vault's ledger: its own custodian's opening of it, or the one a custodian of the receiving
                // vault keeps for the merge — either way only while it opens the pair the chain holds for that ledger
                let (from, asset) = self.merge_key(key)?;
                let (r, rb, m, mb) = if self.vault_here() == from { self.fresh_opening_for_asset(asset)? } else { self.merge_held_opening(from, asset)? };
                (crate::peg::PegLedger::commits_of_opening(r, rb, m, mb) == self.reserve_commits_of(key)?)
                    .then(|| postcard::to_stdvec::<ReservePair>(&(r, rb, m, mb)).ok())
                    .flatten()
            }
            KIND_STAKERS_PAID => {
                if self.custodian_paid_seal.is_empty() || Self::paid_commit_of(&self.custodian_paid_seal) != self.peg.stake_paid_commit() {
                    return None;
                }
                postcard::to_stdvec::<PaidPair>(&paid_opening(&self.custodian_paid_seal)).ok()
            }
            KIND_PART => {
                // only the giving vault's own custodians hold both: the part they carved and their opening as it left them
                let leg = self.part_leg_of(key)?;
                if self.vault_here() != crate::peg::ledger_vault(key) {
                    return None;
                }
                let part = self.rebalance_held_opening(Node::REBALANCE_PART, leg.asset, leg.part)?;
                let post = self.rebalance_held_opening(Node::REBALANCE_POST, leg.asset, leg.from_post)?;
                postcard::to_stdvec::<(ReservePair, ReservePair)>(&(part, post)).ok()
            }
            _ => None,
        }
    }

    /// Install `body` as this node's opening of `(kind, key)` — only when it opens the chain's commitments NOW, and only through
    /// that opening's one writer. `true` when installed.
    fn opening_install(&mut self, kind: u8, key: u32, body: &[u8]) -> bool {
        use usdm_decider::confidential_solvency as cs;
        match kind {
            KIND_POOL => {
                let Some(o) = crate::chain_object::decode_exact::<PoolOpening>(body) else { return false };
                let now = self.peg.pool_words(key);
                if o.words(now.epoch) != now {
                    return false;
                }
                self.pool_openings.insert(key, o);
                self.persist_pool_openings();
                true
            }
            KIND_RESERVE => {
                let Some((r, rb, m, mb)) = crate::chain_object::decode_exact::<ReservePair>(body) else { return false };
                if Some(crate::peg::PegLedger::commits_of_opening(r, rb, m, mb)) != self.reserve_commits_of(key) {
                    return false;
                }
                // SAFE AT SCALE: a custody-funded ledger is installed only when it is THIS custodian's own vault's, under
                // the ASSET its seals are stored by; a registered wrapped asset under its own id, as it was
                let store = if crate::peg::ledger_asset_checked(key).is_some_and(crate::peg::PegLedger::is_custody_funded) {
                    let Some(asset) = self.own_vault_asset(key) else { return false };
                    asset
                } else {
                    key
                };
                if store == crate::peg::NATIVE_PEG_ASSET_ID {
                    self.set_custodian_opening_seal(seal_opening(r, rb, m, mb));
                } else {
                    self.set_wrapped_opening_seal(store, seal_opening(r, rb, m, mb));
                }
                true
            }
            KIND_MERGE => {
                // the retiring vault's opening, kept by a custodian of the RECEIVING vault for the merge it will prove
                let Some((r, rb, m, mb)) = crate::chain_object::decode_exact::<ReservePair>(body) else { return false };
                let Some((from, asset)) = self.merge_key(key) else { return false };
                if self.vault_here() == from || Some(crate::peg::PegLedger::commits_of_opening(r, rb, m, mb)) != self.reserve_commits_of(key) {
                    return false;
                }
                self.set_merge_held_opening(asset, seal_opening(r, rb, m, mb));
                true
            }
            KIND_PART => {
                // a part FOR this custodian's vault, with the giver's opening as the carve left it: kept only when both open
                // the slot this node's own chain holds and the part is exactly the eighth of both words of that ledger the rule owes
                let Some((part, post)) = crate::chain_object::decode_exact::<(ReservePair, ReservePair)>(body) else { return false };
                let Some(leg) = self.part_leg_of(key) else { return false };
                let into = self.peg.vault_part(crate::peg::ledger_vault(key)).map(|p| p.into);
                let opens = |o: ReservePair| crate::peg::PegLedger::commits_of_opening(o.0, o.1, o.2, o.3);
                if into != Some(self.vault_here()) || opens(part) != leg.part || opens(post) != leg.from_post || !crate::peg::PegLedger::parts_are_one_fraction(&[(part, post)]) {
                    return false;
                }
                self.set_rebalance_held_opening(Node::REBALANCE_IN, leg.asset, part);
                true
            }
            KIND_STAKERS_PAID => {
                let Some((p, pb)) = crate::chain_object::decode_exact::<PaidPair>(body) else { return false };
                if cs::solvency_commit_256([p as u64, (p >> 64) as u64, 0, 0], pb) != self.peg.stake_paid_commit() {
                    return false;
                }
                self.set_custodian_paid_seal(seal_paid(p, pb));
                true
            }
            _ => false,
        }
    }

    /// The asks this node owes now: one per opening it should hold as a bonded custodian — each moved PSM pool, each PSM's reserve
    /// pair, the stakers' paid-out total — whose opening here does not open the chain's commitments. Empty on a node that is not a
    /// custodian, and on every custodian whose openings are current.
    #[must_use]
    pub(crate) fn opening_share_asks(&self) -> Vec<OpeningShare> {
        let Some((me, _)) = self.bonded_custodian_identity() else {
            return Vec::new();
        };
        let me = *me;
        let wanted = self
            .peg
            .pool_asset_ids()
            .into_iter()
            .filter(|a| self.is_psm(*a))
            .map(|a| (KIND_POOL, a))
            // SAFE AT SCALE: of the custody-funded ledgers a custodian holds its OWN vault's alone (one per asset the chain
            // keeps — the asset's own id on a one-vault chain, as it was); every registered wrapped asset by its own id.
            // The registry also names other vaults' ledgers: those are their custodians' to hold, never asked for here.
            .chain(
                crate::peg::CUSTODY_LEDGER_KINDS
                    .iter()
                    .map(|a| self.ledger_here(*a))
                    .chain(self.peg.wrapped_asset_ids().into_iter().filter(|id| !crate::peg::ledger_asset_checked(*id).is_some_and(crate::peg::PegLedger::is_custody_funded)))
                    .filter(|key| self.reserve_commits_of(*key).is_some())
                    .map(|key| (KIND_RESERVE, key)),
            )
            // …and, while a merge INTO this custodian's vault is due, the retiring vault's opening of every ledger it moved
            .chain(self.merge_asks().into_iter().map(|key| (KIND_MERGE, key)))
            // …and every part at rest FOR this custodian's vault that it does not hold yet (spec §3g.1)
            .chain(self.part_asks().into_iter().map(|key| (KIND_PART, key)))
            .chain(std::iter::once((KIND_STAKERS_PAID, 0)));
        wanted
            .filter(|(kind, key)| self.opening_bytes_now(*kind, *key).is_none())
            .filter_map(|(kind, key)| Some(OpeningShare::Ask { kind, key, words: self.opening_target(kind, key)?, from: me }))
            .collect()
    }

    /// The answer to `ask`: this node's opening sealed to the asker, only when this node is a bonded custodian, its opening opens
    /// EXACTLY the commitments the ask names (the same chain state), and the asker is a bonded custodian with a registered custody key.
    #[must_use]
    pub(crate) fn opening_share_answer(&self, ask: &OpeningShare) -> Option<OpeningShare> {
        let OpeningShare::Ask { kind, key, words, from } = ask else { return None };
        let (me, _) = self.bonded_custodian_identity()?;
        if me == from || self.opening_target(*kind, *key)? != *words {
            return None; // ourselves, or another chain state: an opening of ours would not open the asker's commitments
        }
        // SAFE AT SCALE — WHO IS ANSWERED. A vault's reserve pair is its custodians' to hold: a custodian of another vault
        // that names this vault's (public) commitments is not handed this vault's totals. A merge opening goes only to a
        // custodian of the vault this node's own chain says takes this vault's ledgers, and only from a custodian of the
        // retiring vault. On a one-vault chain every bonded custodian is a vault mate, as before.
        match *kind {
            KIND_RESERVE if self.own_vault_asset(*key).is_some() && !self.custody_vault_members(self.vault_here()).is_some_and(|m| m.binary_search(from).is_ok()) => return None,
            KIND_MERGE if self.vault_here() != crate::peg::ledger_vault(*key) || !self.sits_in_the_vault_taking(from, crate::peg::ledger_vault(*key)) => return None,
            // a part goes only from a custodian of the giving vault to a custodian of the vault its slot is for
            KIND_PART
                if self.vault_here() != crate::peg::ledger_vault(*key)
                    || !self
                        .peg
                        .vault_part(crate::peg::ledger_vault(*key))
                        .and_then(|p| self.custody_vault_members(p.into))
                        .is_some_and(|m| m.binary_search(from).is_ok()) =>
            {
                return None
            }
            _ => {}
        }
        let body = self.opening_bytes_now(*kind, *key)?;
        let ek = self.validators.bonded_custodian_eks().into_iter().find(|(id, _)| id == from).map(|(_, ek)| ek)?;
        Some(OpeningShare::Give { kind: *kind, key: *key, words: *words, to: *from, sealed: seal(&ek, &body)? })
    }

    /// Take a give addressed to this custodian: `true` when it opened under this custodian's key, reproduces the chain's CURRENT
    /// commitments for that opening exactly, and was installed (and persisted). Anything else changes nothing.
    pub(crate) fn opening_share_take(&mut self, give: &OpeningShare) -> bool {
        let OpeningShare::Give { kind, key, words, to, sealed } = give else { return false };
        let Some((me, dk)) = self.bonded_custodian_identity() else { return false };
        if me != to {
            return false;
        }
        let dk = dk.clone();
        if self.opening_target(*kind, *key) != Some(*words) || self.opening_bytes_now(*kind, *key).is_some() {
            return false; // the chain moved since the ask, or this node's own opening is current again: nothing to take
        }
        let Some(body) = open(&dk, sealed) else { return false };
        if !self.opening_install(*kind, *key, &body) {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed sentence, an opening kind and a public asset id — no amount, blind, key or owner.
            eprintln!("[opening-share] ⛔ a peer's opening (kind {kind}, asset {key}) does not open the chain's commitments — refused, nothing installed");
            return false;
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed sentence, an opening kind and a public asset id — no amount, blind, key or owner.
        eprintln!("[opening-share] this custodian's opening (kind {kind}, asset {key}) was stale; a peer's sealed opening reproduced the chain's commitments and is installed");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_custodians() -> (Node, Node, Vec<(Vec<u8>, Vec<u8>)>) {
        use crate::node::tests::testnet_party_folding_at_tip;
        let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..2).map(|_| crate::pqauth::ml_dsa_keypair()).collect();
        let (mut a, mut b) = (testnet_party_folding_at_tip(), testnet_party_folding_at_tip());
        for (pk, sk) in &keys {
            let vid = crate::pqauth::pubkey_id(pk);
            let (ek, _) = crate::validator::custody_kem_from_vote_sk(sk);
            for n in [&mut a, &mut b] {
                n.admit_validator(vid, 1_000_000, 0).expect("seated");
                n.register_custody_kem(vid, ek.clone());
            }
        }
        a.set_custodian_identity(crate::pqauth::pubkey_id(&keys[0].0), crate::validator::custody_kem_from_vote_sk(&keys[0].1).1);
        b.set_custodian_identity(crate::pqauth::pubkey_id(&keys[1].0), crate::validator::custody_kem_from_vote_sk(&keys[1].1).1);
        (a, b, keys)
    }

    /// ⭐ A-F19 PIN (two custodians, one ledger state): custodian B's openings are stranded (the state a leg that does not open
    /// leaves), A holds the current ones — the stability pool, the native reserve pair and the stakers' paid-out total. For EACH kind:
    /// (1) B owes an ask and A owes none; (2) A answers, sealed to B; (3) B installs it and its opening is current again.
    /// (4) REFUSED: a give sealed to B carrying an opening that does not open the commitments (a lying peer), a give for commitments
    /// the chain no longer holds, and a give addressed to another custodian. (5) an ask naming other commitments, and an ask from a
    /// non-custodian, are not answered.
    /// TWO-PARTY-REVIEWED: A answers, B takes; every verdict is the taker's own check against its own ledger.
    #[test]
    fn a_stranded_custodian_recovers_every_opening_from_a_peer_and_refuses_a_lying_one() {
        use usdm_decider::confidential_solvency as cs;
        let lanes = usdm_decider::poseidon2_compress::lanes_of;
        let (mut a, mut b, keys) = two_custodians();
        let id_of = |i: usize| crate::pqauth::pubkey_id(&keys[i].0);
        let native = crate::peg::NATIVE_PEG_ASSET_ID;
        // the moved custody state, the same on both ledgers
        let pool = PoolOpening { t: 7_000, t_blind: lanes(&[3, 1, 4, 1]), ..PoolOpening::genesis() };
        let (r, rb, m, mb) = (55_000u128, lanes(&[2, 7, 1, 8]), 33_000u128, lanes(&[1, 6, 1, 8]));
        let (rc, mc) = crate::peg::PegLedger::commits_of_opening(r, rb, m, mb);
        let (p, pb) = (900u128, lanes(&[9, 9, 8, 7]));
        let pc = cs::solvency_commit_256([p as u64, 0, 0, 0], pb);
        for n in [&mut a, &mut b] {
            n.peg_mut_for_test().set_pool_words_for_test(native, pool.words(0));
            n.peg_mut_for_test().set_custody_commits_for_test(rc, mc, pc);
        }
        a.pool_openings.insert(native, pool);
        a.set_custodian_opening_seal(seal_opening(r, rb, m, mb));
        a.set_custodian_paid_seal(seal_paid(p, pb));
        b.pool_openings.insert(native, PoolOpening::genesis());
        b.set_custodian_opening_seal(seal_opening(1, rb, 1, mb));
        b.set_custodian_paid_seal(seal_paid(1, pb));
        // (1)
        assert!(a.opening_share_asks().is_empty(), "CALIBRATION: a custodian whose openings are current owes no ask");
        let asks = b.opening_share_asks();
        let kinds: Vec<(u8, u32)> = asks.iter().map(|x| match x { OpeningShare::Ask { kind, key, .. } => (*kind, *key), _ => (0, 0) }).collect();
        for want in [(KIND_POOL, native), (KIND_RESERVE, native), (KIND_STAKERS_PAID, 0)] {
            assert!(kinds.contains(&want), "⛔ a stranded custodian owes no ask for {want:?}: it asked {kinds:?}");
        }
        for ask in &asks {
            assert_eq!(OpeningShare::decode(&ask.encode()).as_ref(), Some(ask), "the ask round-trips on the wire");
            let OpeningShare::Ask { kind, key, words, .. } = ask.clone() else { unreachable!() };
            // (5) another chain state, a stranger
            assert!(a.opening_share_answer(&OpeningShare::Ask { kind, key, words: [0x11; 32], from: id_of(1) }).is_none(), "⛔ an ask for other commitments was answered");
            assert!(a.opening_share_answer(&OpeningShare::Ask { kind, key, words, from: [0x77; 32] }).is_none(), "⛔ an ask from a non-custodian was answered");
            // (2)
            let give = a.opening_share_answer(ask).expect("⛔ a custodian holding the current opening does not answer");
            assert_eq!(OpeningShare::decode(&give.encode()).as_ref(), Some(&give), "the give round-trips on the wire");
            let OpeningShare::Give { sealed, .. } = give.clone() else { unreachable!() };
            // (4) a lying peer: a well-formed give, sealed to B, whose opening does not open the commitments
            let ek_b = a.validators().bonded_custodian_eks().into_iter().find(|(id, _)| *id == id_of(1)).map(|(_, ek)| ek).expect("B's key");
            let wrong: Vec<u8> = match kind {
                KIND_POOL => postcard::to_stdvec(&PoolOpening { t: 7_001, ..pool }).unwrap(),
                KIND_RESERVE => postcard::to_stdvec::<ReservePair>(&(r + 1, rb, m, mb)).unwrap(),
                _ => postcard::to_stdvec::<PaidPair>(&(p + 1, pb)).unwrap(),
            };
            let lie = OpeningShare::Give { kind, key, words, to: id_of(1), sealed: seal(&ek_b, &wrong).unwrap() };
            assert!(!b.opening_share_take(&lie), "⛔⛔ a peer's opening of kind {kind} that does not open the chain's commitments was installed");
            assert!(b.opening_bytes_now(kind, key).is_none(), "the lie changed nothing");
            assert!(!b.opening_share_take(&OpeningShare::Give { kind, key, words, to: id_of(0), sealed: sealed.clone() }), "⛔ a give addressed to another custodian was taken");
            assert!(!b.opening_share_take(&OpeningShare::Give { kind, key, words: [0xEE; 32], to: id_of(1), sealed }), "⛔ a give for other commitments was taken");
            // (3)
            assert!(b.opening_share_take(&give), "⛔ the stranded custodian refused an honest opening of kind {kind} that opens the chain's commitments");
            assert_eq!(b.opening_bytes_now(kind, key), a.opening_bytes_now(kind, key), "B's opening of kind {kind} is current again");
        }
        assert!(b.opening_share_asks().is_empty(), "B owes no ask any more");
    }
}
