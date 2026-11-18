// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐⭐ SATOSHI (SAT) — the native MonerousD token, issued ONLY as the per-block mining reward (docs/SATOSHI-NATIVE-TOKEN.md).
//!
//! Why it exists (DB-391): a validator bond in USDm is refunded by a reserve theft, because USDm is a claim on the reserve.
//! THORChain's takeover economics hold because its bond asset is not a claim on the pools. SAT is that asset here: its value
//! does not live in the reserve, genesis holds none, and every unit enters through a block that carried valid work.
//!
//! The issuance door is `chain_object::Class::SatoshiReward` (wire tag 23). §9.6 checklist, answered in the spec §3:
//! 1 work — the object rides a block whose header grind the block door verified; 2 proof — the asset-mint validity carrier
//! opens the note to the PUBLIC `(amount, SAT tag)`; 3 conservation — `amount == reward_at(key)`, `key` must equal the
//! carrying block's parent key at the fold, and the fold refuses a reward past [`SATOSHI_CAP`]; no other door mints SAT;
//! 4 replay — the object's own nullifier [`reward_nf`] is retired by the spent SET; 5 bounded work — one object per block,
//! fixed-size fields; 6 parity with `AssetMint` — carrier, in-circuit tag, own nullifier in the lane, owner clue filed from
//! the object; the creator signature and registry path are replaced by the schedule and the protocol-constant asset id.

use crate::hash::Hash32;
use serde::{Deserialize, Serialize};

/// The token's name and ticker.
pub const SATOSHI_NAME: &str = "Satoshi";
pub const SATOSHI_TICKER: &str = "SAT";
pub use crate::sat_schedule::{reward_at, BASE_UNITS_PER_SAT, HALVING_INTERVAL, INITIAL_REWARD, SATOSHI_CAP, SAT_REWARD_CAP, SAT_SET_ASIDE_MAX};

/// The asset id: a protocol constant with no creator and no issue right, so `AssetMint` can never mint it.
#[must_use]
pub fn asset_id() -> [u8; 32] {
    usdm_decider::whir_rec_block::satoshi_asset_id() // ONE definition, shared with the wallet's symbol map
}

/// The in-circuit asset tag every SAT note commits to (the same derivation every asset uses).
#[must_use]
pub fn asset_tag() -> [u64; 3] {
    usdm_decider::whir_rec_block::satoshi_asset_tag()
}

/// The token's logo — the user's original painting (gold-mask hooded statue, Bitcoin pin) with the hoodie recolored black;
/// user-approved 2026-10-04. Served by `/api/token-logo/SAT` as PNG and content-addressed in the descriptor. The one copy
/// lives with the Ion Swap site assets.
pub const LOGO_PNG: &[u8] = include_bytes!("../sites/ionswap-monerousd-org/assets/sat-logo.png");

/// One block's mining reward.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SatoshiRewardTx {
    /// The carrying block's PARENT KEY: the largest GHOSTDAG blue score among its header's parents — consensus data every
    /// node computes the same, and known to the producer when it lays the block (unlike the block's own blue score).
    pub key: u64,
    /// `reward_at(key)` — public by schedule.
    pub amount: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note, `cover::PQ_NOTE_BYTES` whole or
    /// `chain_object::NOTE_REF_BYTES` in carriage form (decode refuses any other width).
    pub note: Vec<u8>,
    /// ⭐ DB-393 B4 — the note's OPENING `o = P(spk ‖ s)`, PUBLIC (Zcash ZIP-213's shielded coinbase). The value is public by
    /// schedule and the asset is SAT, so with `o` the commitment is a function of public data: every node RECOMPUTES
    /// `cm = asset_note_cm(reward_at(key), SAT, o)` — one Poseidon2 evaluation — where a 100,631 B mint carrier (1,828 ms to
    /// prove) stood. ⛔ It spends nothing and names no nullifier (DB-395: spending needs the recipient's `(ask, nk)`;
    /// `nf = P(nk ‖ cm)`), and a fresh `s` per reward makes it fresh per note. Canonical 32-byte digest form; bound into the
    /// block id through the credit-set root.
    pub opening: [u8; 32],
    /// The note's owner as an OLI clue (non-empty, at most `peg_in_tx::OWNER_CLUE_MAX`), filed by every node.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `peg_in_tx::OWNER_CLUE_MAX` — decode refuses wider.
    pub owner_clue: Vec<u8>,
}

/// §22 — the credit-set FRAME bytes a block's reward carriage can take at most (the whole 1,153 B note rides it, plus its
/// public fields and the 4-byte length prefix). Reserved before the mempool fills the sealed sidecar's frame budget, the
/// way the coinbase's space is reserved in Bitcoin Core's `BlockAssembler`. MEASURED by
/// `satoshi_pins::the_reward_carriage_fits_its_frame_reserve`.
pub const REWARD_FRAME_RESERVE: usize = 2_048;

impl SatoshiRewardTx {
    /// The canonical bytes. A struct of integers and byte vectors always serializes under postcard.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        crate::fixed::encode_plain(self)
    }

    /// Refuses rather than guesses: a wrong-width note, an empty or oversized clue, a non-canonical opening, or an amount
    /// that is not the schedule's for its key is not a reward.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<SatoshiRewardTx> {
        let r: SatoshiRewardTx = crate::chain_object::decode_exact(bytes)?;
        // the note travels whole in the object and as a `chain_object::note_ref` (cm ‖ H(note)) in a block's carriage form —
        // both widths are the reward; anything else is not (MEASURED 2026-10-04: full-width-only made the producer's own
        // carriage filter drop every reward, so peers recorded none and the spine roots split)
        let width_ok = r.note.len() == crate::cover::PQ_NOTE_BYTES || r.note.len() == crate::chain_object::NOTE_REF_BYTES;
        if !width_ok
            || r.owner_clue.is_empty()
            || r.owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX
            || crate::spend_frontier::cm_bytes_to_root(&r.opening).is_none()
            || r.amount == 0
            || r.amount != reward_at(r.key)
        {
            return None;
        }
        Some(r)
    }

    /// The framed chain object.
    #[must_use]
    pub fn to_object(&self) -> Vec<u8> {
        Self::to_object_inner(self)
    }

    fn to_object_inner(r: &Self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::SatoshiReward, &r.encode())
    }

    /// The note's commitment bytes (the canonical 32-byte prefix every note carries).
    #[must_use]
    pub fn note_cm(&self) -> Option<[u8; 32]> {
        self.note.get(..32)?.try_into().ok()
    }

    /// ⭐ DB-393 B4 — the no-over-mint / no-wrong-asset gate, by RECOMPUTATION: the note's commitment must be
    /// `asset_note_cm(amount, SAT, o)` for the object's own public opening. `amount` is the schedule's for `key` (decode refuses
    /// any other), so a note opening to more, to another asset, or under another owner tag than the object states is refused
    /// here, at admission and again at the fold (`apply_sat_reward_at_fold`), on every node alike.
    #[must_use]
    pub fn credit_is_authorised(&self) -> bool {
        let (Some(cm), Some(o)) =
            (crate::spend_frontier::note_cm_of(&self.note), crate::spend_frontier::cm_bytes_to_root(&self.opening))
        else {
            return false;
        };
        usdm_decider::whir_rec_block::asset_note_cm(self.amount, asset_tag(), o) == cm
    }

    /// ⭐ SATOSHI §8.1 — build the reward a producer lays: the scheduled amount for the block's parent `key`, SEALED to the
    /// operator wallet's scan key (Bitcoin's coinbase-to-address shape: the node holds no spending key), with an OLI clue at
    /// `("sat", index)` under the recipient's reward-only locator key, so the wallet finds it with its ordinary doubling sweep
    /// and recovers `index` from the tag in one step. `seal_seed` is `None` in production (OS entropy); a TEST build passes
    /// its reproducible block context (`faucet::seal_asset_note`). DB-393 B4: nothing is proved — the object carries the
    /// note's public opening, so building it is one ML-KEM encapsulation and two Poseidon2 evaluations, under any lock.
    #[must_use]
    pub fn build(recipient: &RewardRecipient, index: u64, key: u64, seal_seed: Option<[u8; 32]>) -> Option<SatoshiRewardTx> {
        Self::seal(recipient, index, key, seal_seed)
    }

    /// The reward object for the block's parent `key`: the scheduled amount, the sealed note, its public opening and its clue.
    #[must_use]
    pub fn seal(recipient: &RewardRecipient, index: u64, key: u64, seal_seed: Option<[u8; 32]>) -> Option<SatoshiRewardTx> {
        let amount = reward_at(key);
        if amount == 0 {
            return None;
        }
        // ⛔ DB-395: sealed to the operator wallet's (scan_ek, spk) — the note commits to `P(spk, seed)`, so this node (which
        // holds every byte it sealed) can neither spend its reward nor compute the reward's nullifier.
        let (note, opening) = crate::faucet::seal_asset_note(&recipient.scan_ek, &recipient.spk, amount, asset_tag(), seal_seed)?;
        let owner_clue = reward_clue(&recipient.sat_loc_sk, index);
        let r = SatoshiRewardTx {
            key,
            amount,
            note: note.to_vec(),
            opening: crate::spend_frontier::leaf_to_cm_bytes(opening),
            owner_clue,
        };
        // The object opens its own note: a hard check where the producer lays it, so it never lays one its peers refuse.
        r.credit_is_authorised().then_some(r)
    }
}

/// The OLI domain of mining rewards — the wallet sweeps it beside `"recv"` and `"chg"`.
pub const SAT_LOC_DOMAIN: &str = "sat";

/// Who this node's mining rewards are sealed to (docs §8.1): the operator wallet's PUBLIC scan key, a locator key for the
/// `"sat"` domain only (never the wallet's `loc_sk`), and the next reward's locator index. Provisioned by the wallet over
/// loopback (`/provision_reward_recipient`); a node with none lays no reward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardRecipient {
    /// ML-KEM-768 encapsulation key, 1184 bytes, public.
    pub scan_ek: Vec<u8>,
    /// ⛔ DB-395 — the operator wallet's spend key `spk = P(ask, nk)`, public. Every reward is sealed to it, so the node
    /// holds no spend authority over what it mines (Bitcoin's coinbase-to-address shape, now true of the spend key too).
    pub spk: crate::spend_frontier::Digest4,
    /// The reward-only locator key (`kdf("MonerousD/satoshi/reward-loc/v1", wallet entropy)` in the wallet).
    pub sat_loc_sk: [u8; 32],
    /// The `"sat"` index the NEXT reward's clue takes; advances per laid reward, persisted in place (8 bytes, no growth).
    pub next_index: u64,
}

/// ML-KEM-768 encapsulation key width.
pub const SCAN_EK_BYTES: usize = 1184;

impl RewardRecipient {
    /// A TEST recipient whose keys are a pure function of `seed` (the test node's reproducible miner seed), with its
    /// decapsulation key — the "operator's wallet" a pin holds in-process. The node never stores a dk.
    #[must_use]
    pub fn for_test(seed: &[u8; 32]) -> (RewardRecipient, Vec<u8>) {
        let (scan_ek, dk) = crate::faucet::kem_keypair_from_seed(seed);
        let sat_loc_sk = *blake3::Hasher::new_derive_key("MUSD/test-recipient/sat-loc/v1").update(seed).finalize().as_bytes();
        let (ask, nk) = Self::test_spend_secrets(seed);
        let spk = usdm_decider::whir_rec_block::owner_spk(&ask, &nk);
        (RewardRecipient { scan_ek, spk, sat_loc_sk, next_index: 0 }, dk)
    }
    /// The TEST operator wallet's `(ask, nk)` behind [`Self::for_test`]'s `spk` — what a pin holds to SPEND a reward as its
    /// owner. Production wallets derive theirs from their own seed; the node never holds either.
    #[must_use]
    pub fn test_spend_secrets(seed: &[u8; 32]) -> (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4) {
        let kdf = |domain: &str| -> crate::spend_frontier::Digest4 {
            usdm_decider::poseidon2_compress::hash32_to_digest(
                blake3::Hasher::new_derive_key(domain).update(seed).finalize().as_bytes(),
            )
        };
        (kdf("MUSD/test-recipient/ask/v1"), kdf("MUSD/test-recipient/nk/v1"))
    }
    /// The on-disk form: `ek_len(u32 LE) ‖ ek ‖ spk(32) ‖ sat_loc_sk ‖ next_index(u64 LE)`. DB-395: a file without the spend key
    /// (the pre-DB-395 layout) does not decode — the node lays no reward until its wallet re-provisions.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.scan_ek.len() + 32 + 32 + 8);
        out.extend_from_slice(&(self.scan_ek.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.scan_ek);
        out.extend_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(self.spk));
        out.extend_from_slice(&self.sat_loc_sk);
        out.extend_from_slice(&self.next_index.to_le_bytes());
        out
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<RewardRecipient> {
        let len = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
        if len != SCAN_EK_BYTES || bytes.len() != 4 + len + 32 + 32 + 8 {
            return None;
        }
        let scan_ek = bytes[4..4 + len].to_vec();
        let spk = crate::spend_frontier::cm_bytes_to_root(&bytes[4 + len..4 + len + 32].try_into().ok()?)?;
        let sat_loc_sk: [u8; 32] = bytes[4 + len + 32..4 + len + 64].try_into().ok()?;
        let next_index = u64::from_le_bytes(bytes[4 + len + 64..].try_into().ok()?);
        Some(RewardRecipient { scan_ek, spk, sat_loc_sk, next_index })
    }
}

/// The reward's owner clue: the self-identifying v2 OLI tag at `("sat", index)` — `salt ‖ hint ‖ XOF(L)`, every byte uniform
/// to an observer, recognised by the key holder at ANY index in one step (`reward_clue_index`).
#[must_use]
pub fn reward_clue(sat_loc_sk: &[u8; 32], index: u64) -> Vec<u8> {
    let loc = crate::oli::locator_at(sat_loc_sk, SAT_LOC_DOMAIN, index);
    let salt = crate::oli::address_salt(sat_loc_sk, SAT_LOC_DOMAIN, index);
    let hint = crate::oli::address_index_hint(sat_loc_sk, &salt, index);
    crate::oli::tag_clue_bytes_v2(&loc, &salt, &hint)
}

/// The key holder's one-step recognition: recover `index` from the clue's hint, recompute the whole tag, and answer
/// `Some(index)` only if it is byte-identical. A clue under any other key (or domain) recovers nothing.
#[must_use]
pub fn reward_clue_index(sat_loc_sk: &[u8; 32], clue: &[u8]) -> Option<u64> {
    let salt: [u8; 8] = clue.get(..8)?.try_into().ok()?;
    let hint: [u8; 8] = clue.get(8..16)?.try_into().ok()?;
    let mask = crate::oli::address_index_hint(sat_loc_sk, &salt, 0); // j = 0 ⇒ the mask alone
    let mut j = [0u8; 8];
    for i in 0..8 {
        j[i] = hint[i] ^ mask[i];
    }
    let index = u64::from_le_bytes(j);
    (reward_clue(sat_loc_sk, index) == clue).then_some(index)
}

/// Where this serving node keeps its reward recipient: beside its validator identity (`validator-<port>.reward`), written
/// through the custody keystore like the identity files (an opted-in seal applies).
#[must_use]
pub fn reward_recipient_path() -> std::path::PathBuf {
    crate::validator::node_vote_key_path().with_extension("reward")
}

/// The persisted recipient at `path`, if any and well-formed. O1-INFINITY-REVIEWED: one fixed-size file (1,260 B).
#[must_use]
pub fn load_reward_recipient_at(path: &std::path::Path) -> Option<RewardRecipient> {
    RewardRecipient::decode(&crate::keystore::read_key_file(path).ok()?)
}

/// ⭐ SATOSHI §8.2 — install `(scan_ek, spk, sat_loc_sk)` as this node's reward recipient (the wallet's call). The ek must parse
/// and encapsulate, and `spk` must be a canonical digest (DB-395: rewards are sealed to the wallet's spend key, never to a
/// key this node could hold); the same recipient re-provisioned keeps its counter and only moves it FORWARD to `from_index`
/// (so a wallet re-provisioning after a node rebuild passes one past the highest `"sat"` index it has seen and no locator is
/// reused); a different recipient REPLACES (the operator's wallet decides who mines for it — the old recipient's notes are
/// already on chain). `Ok(rc)` is what was written. O1-INFINITY-REVIEWED: one fixed-size file; never chain state.
pub fn provision_reward_recipient_at(
    path: &std::path::Path,
    scan_ek: &[u8],
    spk_bytes: &[u8; 32],
    sat_loc_sk: [u8; 32],
    from_index: u64,
) -> Result<RewardRecipient, &'static str> {
    let Some(spk) = crate::spend_frontier::cm_bytes_to_root(spk_bytes) else {
        return Err("REWARD_RECIPIENT_SPEND_KEY_MALFORMED");
    };
    if scan_ek.len() != SCAN_EK_BYTES || crate::faucet::seal_asset_note(scan_ek, &spk, 1, asset_tag(), Some([0u8; 32])).is_none() {
        return Err("REWARD_RECIPIENT_KEY_MALFORMED");
    }
    let prior = match crate::keystore::read_key_file(path) {
        Ok(bytes) => RewardRecipient::decode(&bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) if crate::keystore::is_locked(&e) => return Err("REWARD_RECIPIENT_LOCKED"),
        Err(_) => return Err("REWARD_RECIPIENT_UNREADABLE"),
    };
    let next_index = match prior {
        Some(p) if p.scan_ek == scan_ek && p.spk == spk && p.sat_loc_sk == sat_loc_sk => p.next_index.max(from_index),
        _ => from_index,
    };
    let rc = RewardRecipient { scan_ek: scan_ek.to_vec(), spk, sat_loc_sk, next_index };
    crate::keystore::write_key_file(path, &rc.encode()).map_err(|_| "REWARD_RECIPIENT_WRITE_FAILED")?;
    Ok(rc)
}

/// Persist an advanced counter in place (the recipient file rewritten at its fixed size). A failure is logged once per
/// call and never stops production: the clue index is a wallet-side convenience, not consensus.
pub fn persist_reward_recipient_at(path: &std::path::Path, rc: &RewardRecipient) {
    if let Err(e) = crate::keystore::write_key_file(path, &rc.encode()) {
        eprintln!("[sat-reward] ⛔ could not persist the reward recipient's counter: {e}");
    }
}

pub use crate::sat_schedule::{bonder_share_bps, custody_rate};

/// The reward's OWN nullifier: one per note commitment, retired by the spent set, so a copied reward credits nothing.
#[must_use]
pub fn reward_nf(note_cm: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(32 + 32);
    pre.extend_from_slice(b"MONEROUSD-SAT-REWARD-NF-v1");
    pre.extend_from_slice(note_cm);
    crate::cover::canonical_tag_of_hash(Hash32::hash(&pre).as_bytes())
}

/// The parent key and parents digest of a header's parents, read from a DAG: the largest blue score among them, and the
/// hash of the parent ids in header order. `None` when a parent is not held (the fold waits for it anyway).
#[must_use]
pub fn parent_key_of(dag: &crate::dag::Dag, parents: &[crate::block::BlockId]) -> Option<(u64, Hash32)> {
    let mut key = 0u64;
    let mut buf = Vec::with_capacity(32 * parents.len());
    for p in parents {
        key = key.max(dag.get(p)?.blue_score);
        buf.extend_from_slice(p.as_bytes());
    }
    Some((key, Hash32::hash(&buf)))
}

/// A reward's stated key is in force when it is at or below the carrying block's parent key and in the same era. The
/// reward is sealed under the proof, before the block's parents are named (`Node::rebind_parents_at_proof_finish`), so the
/// stated key may trail the parent key by the blocks that arrived while the proof ran. The amount is `reward_at(stated)`,
/// and one era holds one amount, so a block is paid exactly what the schedule pays at its parent key: stating an older key
/// to reach a richer era is refused, and the 21,000,000 cap is unmoved. cons: none in value; a block whose parents cross a
/// halving keeps its template parents (one block per four years).
#[must_use]
pub fn reward_key_in_force(stated: u64, parent_key: Option<u64>) -> bool {
    parent_key.is_some_and(|k| stated <= k && stated / HALVING_INTERVAL == k / HALVING_INTERVAL)
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// An older key cannot reach a richer era, a future key is refused, and a held block has no reward.
    #[test]
    fn a_stated_key_is_in_force_only_at_or_below_the_parent_key_in_its_era() {
        let h = HALVING_INTERVAL;
        assert!(reward_key_in_force(100, Some(100)), "the parent key itself");
        assert!(reward_key_in_force(100, Some(116)), "a key the parents moved past while the proof ran");
        assert_eq!(reward_at(100), reward_at(116), "one era, one amount: nothing is gained by stating the older key");
        assert!(!reward_key_in_force(h - 1, Some(h)), "⛔ an older era's richer reward");
        assert!(reward_at(h - 1) > reward_at(h), "PRECONDITION: the older era really pays more");
        assert!(!reward_key_in_force(0, Some(3 * h)), "⛔ the first era's reward, stated forever");
        assert!(!reward_key_in_force(117, Some(116)), "⛔ a key past the parents");
        assert!(!reward_key_in_force(100, None), "⛔ no parent key held, no reward");
    }

    #[test]
    fn the_halving_interval_is_four_years_at_the_mesh_target() {
        let spacing_ms = crate::params::ChainParams::default().target_spacing_ms;
        assert_eq!(spacing_ms, crate::dag::MESH_TARGET_SPACING_MS, "the default IS the derived target");
        assert_eq!(crate::sat_schedule::SCHEDULE_TARGET_SPACING_MS, spacing_ms, "the schedule is laid on the chain's own target");
        let four_years_ms: u64 = 4 * 36_525 * 864_000;
        assert_eq!(HALVING_INTERVAL, four_years_ms / spacing_ms, "four years at the governance default");
        // SAT per year kept: the first era issues half the reward cap over four years, at any target (to rounding)
        let per_era = u128::from(INITIAL_REWARD) * u128::from(HALVING_INTERVAL);
        let half_cap = u128::from(crate::sat_schedule::SAT_REWARD_CAP) / 2;
        assert!(per_era <= half_cap && half_cap - per_era < u128::from(HALVING_INTERVAL), "the first era issues half the cap");
    }

    /// The schedule sums to at most the cap, halves every era, and ends at zero — measured by walking every era.
    #[test]
    fn the_schedule_never_issues_past_the_cap_and_halves_every_era() {
        let mut total: u128 = 0;
        for era in 0..64u64 {
            let r = reward_at(era * HALVING_INTERVAL);
            if era > 0 {
                assert_eq!(r, reward_at((era - 1) * HALVING_INTERVAL) >> 1, "era {era} halves the one before");
            }
            assert_eq!(r, reward_at(era * HALVING_INTERVAL + HALVING_INTERVAL - 1), "constant within era {era}");
            total += u128::from(r) * u128::from(HALVING_INTERVAL);
        }
        println!("[satoshi] schedule at exactly one block per key: {total} base units of a {SAT_REWARD_CAP} reward cap ({SATOSHI_CAP} supply cap)");
        // §BR-13: rewards sum to 19M; rewards + the 2M set-aside bound never pass the 21M supply cap.
        assert!(total <= u128::from(SAT_REWARD_CAP), "the schedule alone never passes the REWARD cap (19M)");
        assert!(total * 1000 >= u128::from(SAT_REWARD_CAP) * 999, "and it issues the reward cap to within 0.1%");
        assert!(total + u128::from(SAT_SET_ASIDE_MAX) <= u128::from(SATOSHI_CAP), "⛔ rewards + the set-aside bound pass 21M");
        // §BR-13 holds per YEAR, not per block: the reward per block is what spreads half the reward cap over four years at the
        // chain's derived target (3,762,960 base units at the 500 ms the literal here was written for; it scales with the
        // target, and a literal went red as soon as the target moved, A-F60)
        let blocks_a_year = 36_525 * 864_000 / crate::dag::MESH_TARGET_SPACING_MS;
        let per_year = u128::from(INITIAL_REWARD) * u128::from(blocks_a_year);
        let want = u128::from(SAT_REWARD_CAP) / 8; // half the cap over the first four years
        assert!(per_year.abs_diff(want) * 1000 <= want, "§BR-13: the first era issues an eighth of the reward cap a year: {per_year} vs {want}");
        assert_eq!(reward_at(63 * HALVING_INTERVAL), 0, "issuance ends");
    }

    /// A built reward verifies; every tamper (amount, key, opening, note byte, foreign asset) is refused at decode or by the
    /// recomputation (DB-393 B4).
    #[test]
    fn a_built_reward_verifies_and_every_tamper_is_refused() {
        let (rc, dk) = RewardRecipient::for_test(&[7u8; 32]);
        let r = SatoshiRewardTx::build(&rc, 3, 1_000, Some([5u8; 32])).expect("a reward builds");
        assert_eq!(r.amount, INITIAL_REWARD);
        let (amount, _seed, asset) = crate::faucet::scan_asset_note(&r.note, &dk, &rc.spk).expect("the recipient's wallet scans its reward");
        assert_eq!((amount, asset), (INITIAL_REWARD, asset_tag()), "sealed to the recipient, denominated in SAT");
        assert_eq!(reward_clue_index(&rc.sat_loc_sk, &r.owner_clue), Some(3), "the clue names its index to the key holder");
        let (other, _) = RewardRecipient::for_test(&[8u8; 32]);
        assert_eq!(reward_clue_index(&other.sat_loc_sk, &r.owner_clue), None, "⛔ a stranger's key recognised the clue");
        assert_eq!(reward_clue_index(&rc.sat_loc_sk, &reward_clue(&rc.sat_loc_sk, u64::MAX - 1)), Some(u64::MAX - 1), "any index, one step");
        assert_eq!(RewardRecipient::decode(&rc.encode()), Some(rc.clone()), "the on-disk form round-trips");
        assert!(RewardRecipient::decode(&rc.encode()[..rc.encode().len() - 1]).is_none(), "a truncated file is not a recipient");
        let back = SatoshiRewardTx::decode(&r.encode()).expect("round-trips");
        assert!(back.credit_is_authorised(), "the honest reward's opening recomputes its note's commitment at (amount, SAT)");
        let mut more = r.clone();
        more.amount += 1;
        assert!(SatoshiRewardTx::decode(&more.encode()).is_none(), "a reward that is not the schedule's is not a reward");
        let mut later = r.clone();
        later.key = HALVING_INTERVAL;
        later.amount = reward_at(later.key);
        let later = SatoshiRewardTx::decode(&later.encode()).expect("schedule-consistent");
        assert!(!later.credit_is_authorised(), "the opening binds the note to the scheduled amount it was sealed at");
        let mut bad = r.clone();
        bad.opening = crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&[0xBAD, 2, 3, 4]));
        assert!(!bad.credit_is_authorised(), "another owner tag does not open the note");
        let mut swapped = r.clone();
        swapped.note[0] ^= 1;
        assert!(!swapped.credit_is_authorised(), "the opening opens ONE commitment");
        let o = crate::spend_frontier::cm_bytes_to_root(&r.opening).expect("canonical");
        let other_tag = usdm_decider::whir_rec_block::wrapped_asset_tag(&[9u8; 32]);
        let cm2 = usdm_decider::whir_rec_block::asset_note_cm(r.amount, other_tag, o);
        let mut foreign = r.clone();
        foreign.note[..crate::spend_frontier::NOTE_CM_BYTES].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm2));
        assert!(!foreign.credit_is_authorised(), "a note of another asset is not SAT, under the same owner tag");
        let mut noncanonical = r.clone();
        noncanonical.opening = [0xFF; 32];
        assert!(SatoshiRewardTx::decode(&noncanonical.encode()).is_none(), "a non-canonical opening is not a reward");
        let cm = r.note_cm().expect("cm");
        assert_eq!(reward_nf(&cm), reward_nf(&cm));
        assert_ne!(reward_nf(&cm), reward_nf(&swapped.note_cm().expect("cm")));
    }

    /// §10.5–§10.8 — the pendulum is thornode's `getPoolShare` with public SAT inputs: all income to bonders at or below one
    /// third of issued SAT bonded; 50/50 at two thirds; one third when everything is bonded; a dust split of the same total
    /// weight cannot move it (it reads the TOTAL); and the bonders' rate is the base at 50/50 and 2× at full share.
    #[test]
    fn the_pendulum_is_getpoolshare_on_public_sat_figures_and_the_bonders_rate_swings_around_its_base() {
        let s = 3_000_000u128; // issued SAT (base units)
        assert_eq!(bonder_share_bps(0, 0), 10_000, "genesis: nothing issued, nothing bonded");
        assert_eq!(bonder_share_bps(s / 3, s), 10_000, "securing ≤ secured ⇒ everything to bonders");
        assert_eq!(bonder_share_bps(s / 6, s), 10_000, "thin bond ⇒ everything to bonders");
        assert_eq!(bonder_share_bps(2 * s / 3, s), 5_000, "the 2:1 target: two thirds of issued SAT bonded ⇒ 50/50");
        assert_eq!(bonder_share_bps(s, s), 3_333, "everything bonded ⇒ one third");
        let one_seat = bonder_share_bps(1_234_567, s);
        let dust_total: u128 = (0..100).map(|_| 12_345u128).sum::<u128>() + 67; // the same total, split 101 ways
        assert_eq!(dust_total, 1_234_567);
        assert_eq!(bonder_share_bps(dust_total, s), one_seat, "⛔ splitting a bond into dust seats moved the share");
        assert_eq!(custody_rate(1_000, 5_000), 1_000, "the base at 50/50");
        assert_eq!(custody_rate(1_000, 10_000), 2_000, "2× while bond is thin");
        assert_eq!(custody_rate(1_000, 3_333), 666, "falls as bond grows");
        assert_eq!(custody_rate(1_000, 20_000), 2_000, "a share is clamped to 10,000 bps");
        assert_eq!(bonder_share_bps(u128::from(u64::MAX), u128::from(u64::MAX)), 3_333, "no overflow at the extremes");
    }
}
