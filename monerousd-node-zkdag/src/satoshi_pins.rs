// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ SATOSHI — the issuance door's pins, through a PEER fed only blocks (docs/SATOSHI-NATIVE-TOKEN.md §3–4).
//! Every rogue arm is measured as a DELTA of the peer's issued total around the one block under judgement, after the
//! block's parents are delivered first, so an assertion can only see what that block did.

use crate::block::Block;
use crate::hash::Hash32;
use crate::node::Node;
use crate::relay::RelayOutcome;
use crate::satoshi::{parent_key_of, reward_at, reward_clue_index, reward_nf, RewardRecipient, SatoshiRewardTx, SATOSHI_CAP};

/// The whole 1,153-byte reward note a block carries for commitment `cm` (the credit set holds the 64-byte carriage form;
/// the note itself rides `output_notes`).
fn reward_note_bytes(blk: &Block, cm: &[u8; 32]) -> Vec<u8> {
    blk.output_notes
        .chunks(crate::cover::PQ_NOTE_BYTES)
        .find(|n| n.len() == crate::cover::PQ_NOTE_BYTES && n[..32] == cm[..])
        .expect("the block carries the reward note whole")
        .to_vec()
}

/// A rogue producer's reward sealed to ITS OWN recipient (a pure function of `seed`), at clue index `index`.
fn rogue_reward(seed: u8, index: u64, key: u64, d: &Hash32) -> SatoshiRewardTx {
    let (rc, _dk) = RewardRecipient::for_test(&[seed; 32]);
    SatoshiRewardTx::build(&rc, index, key, Some(*d.as_bytes())).expect("builds")
}

/// A test node's recipient and the secrets its operator's wallet would hold (DB-395: its decapsulation key AND the `(ask, nk)`
/// behind the recipient's `spk` — the node holds neither).
fn wallet_of(node: &Node) -> (RewardRecipient, crate::faucet::RecipientSecrets) {
    let (rc, _dk) = RewardRecipient::for_test(&node.miner_seed());
    assert_eq!(
        node.reward_recipient().map(|r| (r.scan_ek.clone(), r.spk)),
        Some((rc.scan_ek.clone(), rc.spk)),
        "the node seals to this wallet's address"
    );
    (rc, crate::faucet::RecipientSecrets::for_test(&node.miner_seed()))
}

/// The SAT rewards a block carries, decoded. A credit set that does not parse fails the pin.
fn rewards_in(blk: &Block) -> Vec<SatoshiRewardTx> {
    crate::block::credit_set_iter(&blk.credit_set, crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).as_ref(), &blk.wide_objects)
        .expect("the block's credit set parses")
        .iter()
        .filter_map(|o| match crate::chain_object::unframe(o) {
            Some((crate::chain_object::Class::SatoshiReward, p)) => SatoshiRewardTx::decode(p),
            _ => None,
        })
        .collect()
}

/// `node_b` lays a block, then its credit set is replaced by `rewards` (notes, commitments, lane tags and roots rewritten
/// to match), exactly as a rogue producer would rewrite its own block before publishing it.
fn rogue_block_with_rewards(node_b: &mut Node, ts: u64, seed: &[u8], make: impl FnOnce(u64, &Hash32) -> Vec<SatoshiRewardTx>) -> Block {
    let mut blk = node_b.produce(ts, Hash32::hash(seed), Hash32::hash(b"sat-rogue-mc")).expect("the rogue lays its block");
    let (key, digest) = parent_key_of(node_b.dag(), &blk.header.parents).expect("the rogue holds its own parents");
    let rewards = make(key, &digest);
    blk.output_notes = rewards.iter().flat_map(|r| r.note.clone()).collect();
    blk.header.output_notes_root = crate::block::da_notes_root_of(&blk.output_notes);
    blk.note_commitments = node_b.note_commitment_carrier_for_test(&blk.output_notes);
    blk.header.note_commitments_root = Hash32::hash(&blk.note_commitments);
    let carriages: Vec<Vec<u8>> =
        rewards.iter().map(|r| crate::chain_object::carriage_of(&r.to_object()).expect("a reward has a carriage form")).collect();
    // §22b: sealed exactly as a producer seals — a carriage wider than the inline bound rides as a reference, its bytes beside
    (blk.credit_set, blk.wide_objects) = crate::node::tests::sealed_credit_parts(&blk, &carriages);
    blk.header.credit_set_root = crate::block::credit_set_root_of(&blk.credit_set);
    for r in &rewards {
        blk.nullifier_proof.padded_tags.push(reward_nf(&r.note_cm().expect("a full-width note")));
    }
    blk.header.nullifier_tags_root = crate::block::nullifier_tags_root_of(&blk.nullifier_proof.padded_tags);
    let own: Vec<[u8; 32]> = rewards.iter().map(|r| reward_nf(&r.note_cm().expect("a full-width note"))).collect();
    crate::node::tests::lay_tag_evidence_for_test(node_b, &mut blk, &own);
    blk
}

/// Deliver every parent of `blk` that `node_a` lacks (from the rogue, which holds them — its own UNMUTATED blocks, each
/// with an honest reward), fold, and return `(the peer's issued total, the honest reward those parents carry)`. A delivered
/// parent is a SIDE block until the judged block merges it, so its reward folds in the judged block's step: the expected
/// delta of that step is the judged block's own contribution PLUS this (MEASURED 2026-10-04 23:1x: the "doubled" arm read
/// +2 rewards — one the doubled block's, one a merged honest parent's — and the fold had refused the second reward exactly
/// as designed).
/// Hand `node_a` every parent of `blk` it lacks (the rogue's HONEST blocks, each with its own reward), and return the SAT
/// issued on `node_a` BEFORE any of them landed, the sum of their rewards, and their reward commitments.
/// ⚠ A delivered honest parent may GRAFT (its note recorded) and yet never FOLD here: it is a sibling of a rogue block the
/// peer already judged and folded, so it lands below the moving fold cursor — DB-379's stranded-block class (filed, spec'd
/// as the canonical re-walk, deferred), not this pin's subject. MEASURED 2026-10-05 00:50 (batch7): every honest commitment
/// recorded, exactly one of the doubled rewards credited, and `sat_issued` one honest reward short. So the totals below are
/// BOUNDS that admit the stranded parent explicitly; the per-note verdicts (`recorded`) carry the exact claim.
fn deliver_parents(node_a: &mut Node, node_b: &Node, blk: &Block, at: u64) -> (u64, u64, Vec<[u8; 32]>) {
    let before = node_a.peg().sat_issued();
    let mut merged_honest: u64 = 0;
    let mut merged_cms: Vec<[u8; 32]> = Vec::new();
    for p in &blk.header.parents {
        if node_a.dag().get(p).is_none() {
            let parent = node_b.full_block_by_id(p).expect("the rogue holds its parents and its honest twin");
            for r in rewards_in(&parent) {
                merged_honest += r.amount;
                merged_cms.push(r.note_cm().expect("a full-width note"));
            }
            let out = node_a.ingest_block_preverified(parent, at);
            assert!(matches!(out, RelayOutcome::Added(_)), "CALIBRATION: the honest parent grafts on the peer: {out:?}");
        }
    }
    let _ = node_a.fold_canonical_records();
    (before, merged_honest, merged_cms)
}
/// `after` is `before` plus what the judged block honestly minted (`expected`), plus the honest parents' rewards ONLY IF they
/// folded (DB-379 may strand a parent, see `deliver_parents`): never more, never less than the judged block's own credit.
fn within_honest_bounds(after: u64, before: u64, merged: u64, expected: u64) -> bool {
    after >= before + expected && after <= before + merged + expected
}
/// Which of `cms` the peer recorded (credited) — the per-note view behind every total below.
fn recorded(node_a: &Node, cms: &[[u8; 32]]) -> Vec<bool> {
    cms.iter().map(|cm| node_a.holds_record_with_cm(cm)).collect()
}

/// The peer judges `blk` (grafts it and folds) and returns its issued total after.
fn judge(node_a: &mut Node, blk: Block, at: u64, what: &str) -> u64 {
    let out = node_a.ingest_block_preverified(blk, at);
    eprintln!("[satoshi-pin] the peer's verdict on {what}: {out:?}");
    assert!(matches!(out, RelayOutcome::Added(_)), "CALIBRATION: the block grafts — the reward reaches its door: {out:?}");
    let _ = node_a.fold_canonical_records();
    node_a.peg().sat_issued()
}

/// ⭐ CONTROL — a produced block mints EXACTLY its scheduled reward, once, on the producer and on a peer fed only blocks,
/// and the reward's note is recorded on both.
#[test]
fn a_produced_block_mints_exactly_its_scheduled_sat_reward_on_the_producer_and_a_peer_fed_only_blocks() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    assert_eq!(node_a.peg().sat_issued(), 0, "PRECONDITION: genesis issues no SAT");
    let blk = node_a.produce(5_000, Hash32::hash(b"sat-honest-1"), Hash32::hash(b"mc")).expect("node_a lays a block");
    let rewards = rewards_in(&blk);
    assert_eq!(rewards.len(), 1, "the block carries exactly one mining reward");
    let (key, _) = parent_key_of(node_a.dag(), &blk.header.parents).expect("parents held");
    assert_eq!((rewards[0].key, rewards[0].amount), (key, reward_at(key)), "the schedule's amount at the block's parent key");
    let _ = node_a.fold_canonical_records();
    assert_eq!(node_a.peg().sat_issued(), rewards[0].amount, "the producer issued exactly the reward");
    assert!(matches!(node_b.ingest_block(blk, 5_500), RelayOutcome::Added(_)), "the peer grafts the block");
    let _ = node_b.fold_canonical_records();
    assert_eq!(node_b.peg().sat_issued(), node_a.peg().sat_issued(), "the peer fed only the block issued the same");
    let cm = rewards[0].note_cm().expect("cm");
    assert!(node_a.holds_record_with_cm(&cm) && node_b.holds_record_with_cm(&cm), "the reward note is recorded on both nodes");
    // and the next block issues the next reward, again on both
    let next = node_a.produce(7_000, Hash32::hash(b"sat-honest-2"), Hash32::hash(b"mc")).expect("the next block");
    let r2 = rewards_in(&next);
    assert_eq!(r2.len(), 1);
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(next, 7_500), RelayOutcome::Added(_)));
    let _ = node_b.fold_canonical_records();
    assert_eq!(node_a.peg().sat_issued(), rewards[0].amount + r2[0].amount);
    assert_eq!(node_b.peg().sat_issued(), node_a.peg().sat_issued(), "two blocks, two rewards, the same total on both");
}

/// ⛔ ROGUE PRODUCER — every way to mint more than the schedule pays mints NOTHING on the peer: a reward stating a key that
/// is not its block's (same era, so the amount and carrier are internally valid), a forged carrier, a second reward in one
/// block (the first applies, the second does not), and one reward replayed in a sibling block with the same parents.
#[test]
fn a_rogue_reward_at_a_wrong_key_with_a_forged_carrier_doubled_or_replayed_mints_nothing_extra_on_the_peer() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    // a shared past: node_a's block reaches node_b
    let base = node_a.produce(5_000, Hash32::hash(b"sat-base"), Hash32::hash(b"mc")).expect("base");
    assert!(matches!(node_b.ingest_block(base, 5_500), RelayOutcome::Added(_)));
    let _ = node_a.fold_canonical_records();
    let _ = node_b.fold_canonical_records();

    // (i) a key that is not the block's own
    let wrong = rogue_block_with_rewards(&mut node_b, 8_000, b"sat-wrong-key", |key, d| {
        vec![rogue_reward(0x11, 0, key + 1, d)]
    });
    let wrong_cm = rewards_in(&wrong)[0].note_cm().expect("cm");
    let (before, merged, parents) = deliver_parents(&mut node_a, &node_b, &wrong, 8_500);
    let after = judge(&mut node_a, wrong, 8_600, "a reward stating another key");
    assert!(!node_a.holds_record_with_cm(&wrong_cm), "⛔ a reward at a key that is not its block's was RECORDED on the peer");
    assert!(recorded(&node_a, &parents).iter().all(|b| *b), "CONTROL: the honest parents' rewards are recorded: {:?}", recorded(&node_a, &parents));
    assert!(within_honest_bounds(after, before, merged, 0), "⛔ a reward at a key that is not its block's minted SAT on the peer: {before} → {after} (merged {merged})");

    // (ii) a forged opening (DB-393 B4 C2): the note's commitment does not recompute under the object's own `o`
    let forged = rogue_block_with_rewards(&mut node_b, 10_000, b"sat-forged", |key, d| {
        let mut r = rogue_reward(0x22, 0, key, d);
        r.opening = crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&[0x0F0F, 2, 3, 4]));
        vec![r]
    });
    let forged_cm = rewards_in(&forged)[0].note_cm().expect("cm");
    let (before, merged, parents) = deliver_parents(&mut node_a, &node_b, &forged, 10_500);
    let after = judge(&mut node_a, forged, 10_600, "a reward whose opening does not open its note");
    assert!(!node_a.holds_record_with_cm(&forged_cm), "⛔ a forged opening's note was RECORDED on the peer");
    assert!(recorded(&node_a, &parents).iter().all(|b| *b), "CONTROL: the honest parents' rewards are recorded: {:?}", recorded(&node_a, &parents));
    assert!(within_honest_bounds(after, before, merged, 0), "⛔ a forged opening minted SAT on the peer: {before} → {after} (merged {merged})");

    // (iii) two rewards in one block: exactly one applies
    let original = rogue_block_with_rewards(&mut node_b, 12_000, b"sat-replay", |key, d| {
        vec![rogue_reward(0x55, 0, key, d)]
    });
    let mut sibling = original.clone();
    sibling.header.timestamp += 1; // a different block id over the same parents and the same reward bytes
    let one = rewards_in(&original)[0].amount;
    let original_cm = rewards_in(&original)[0].note_cm().expect("cm");
    let (before, merged, parents) = deliver_parents(&mut node_a, &node_b, &original, 12_500);
    let mid = judge(&mut node_a, original, 12_600, "a reward");
    assert!(node_a.holds_record_with_cm(&original_cm), "CONTROL: the first carriage's reward is recorded");
    assert!(recorded(&node_a, &parents).iter().all(|b| *b), "CONTROL: the honest parents' rewards are recorded: {:?}", recorded(&node_a, &parents));
    assert!(within_honest_bounds(mid, before, merged, one), "CONTROL: the first carriage mints its reward: {before} → {mid} (merged {merged}, one {one})");
    let after = judge(&mut node_a, sibling, 12_700, "the same reward replayed in a sibling block");
    assert_eq!(after, mid, "⛔ a replayed reward minted a second time on the peer");
    // ORDER: the doubled case runs LAST. Its block's lane carries a tag whose object the fold REFUSES (the second reward), and
    // in this bare fixture (no band prover) the fold then WAITS at later spends ("[respend] ⏸ DB-353 §13.6 … admitted set is
    // unknown here") — the in-process artifact measured 2026-10-03 (the hub's band worker resolves it: d3036df). A case judged
    // after it would read an honest under-count; nothing here is an over-mint.
    let doubled = rogue_block_with_rewards(&mut node_b, 14_000, b"sat-doubled", |key, d| {
        vec![
            rogue_reward(0x33, 0, key, d),
            rogue_reward(0x44, 0, key, d),
        ]
    });
    let one = rewards_in(&doubled)[0].amount;
    let both: Vec<[u8; 32]> = rewards_in(&doubled).iter().map(|r| r.note_cm().expect("cm")).collect();
    let (before, merged, parents) = deliver_parents(&mut node_a, &node_b, &doubled, 14_500);
    let after = judge(&mut node_a, doubled, 14_600, "two rewards in one block");
    let got = recorded(&node_a, &both);
    assert_eq!(got.iter().filter(|b| **b).count(), 1, "⛔ a block with two rewards credited {got:?} (exactly ONE is the rule)");
    assert!(recorded(&node_a, &parents).iter().all(|b| *b), "CONTROL: the honest parents' rewards are recorded: {:?}", recorded(&node_a, &parents));
    assert!(within_honest_bounds(after, before, merged, one), "⛔ a block minted more than one reward (or none) on the peer: {before} → {after} (merged {merged}, one {one})");

    // (iv) one reward replayed in a sibling block with the SAME parents (so the same key): it mints once across both
}

/// ⛔ NO OTHER DOOR MINTS SAT: an asset mint naming SAT's id is refused at admission, whatever else it carries.
#[test]
fn an_asset_mint_naming_sat_is_refused_at_admission() {
    let m = crate::asset_tx::AssetMintTx {
        asset_id: crate::satoshi::asset_id(),
        kind: crate::asset_tx::AssetKind::Token,
        amount: 1_000,
        note: vec![1u8; crate::cover::PQ_NOTE_BYTES],
        mint_carrier: vec![2u8; 4],
        owner_clue: vec![3u8; 4],
        creator_pubkey: vec![1u8; 8],
        creator_sig: vec![2u8; 8],
        symbol: "SAT".into(),
        asset_name: "Satoshi".into(),
        registry_path: Vec::new(),
        registry_dirs: Vec::new(),
        logo: [0u8; 32],
        collection: String::new(),
    };
    let blob = crate::chain_object::frame(crate::chain_object::Class::AssetMint, &postcard::to_allocvec(&m).expect("encodes"));
    assert!(!crate::chain_object::admissible(&blob, 0, u64::MAX, false), "⛔ an asset mint could name SAT");
}

/// ⛔ THE CAP HOLDS: the reward door credits up to exactly 19,000,000 SAT (§BR-13: rewards sum to 19M; the 2M developer
/// set-aside bound makes the 21M supply cap) and refuses the base unit past it.
#[test]
fn the_issued_total_never_passes_the_twenty_one_million_cap() {
    use crate::satoshi::{SAT_REWARD_CAP, SAT_SET_ASIDE_MAX};
    assert_eq!(SAT_REWARD_CAP + SAT_SET_ASIDE_MAX, SATOSHI_CAP, "§BR-13: rewards + the set-aside bound = the 21M supply cap");
    let mut peg = crate::peg::PegLedger::new(crate::peg::DEFAULT_MINT_RATIO_BPS);
    assert!(peg.credit_sat_reward(SAT_REWARD_CAP - 5));
    assert!(!peg.credit_sat_reward(6), "⛔ one base unit past the reward cap was credited");
    assert_eq!(peg.sat_issued(), SAT_REWARD_CAP - 5, "a refused credit moves nothing");
    assert!(peg.credit_sat_reward(5));
    assert_eq!(peg.sat_issued(), SAT_REWARD_CAP);
    assert!(!peg.credit_sat_reward(1), "⛔ the reward cap is not final");
    assert!(peg.sat_issued() + SAT_SET_ASIDE_MAX <= SATOSHI_CAP, "⛔ every reward plus the set-aside bound passes 21M");
}

/// ⭐⭐⭐ DB-391 CLOSED BY CONSTRUCTION — custody weight is SAT. A node mines a reward, builds a SAT custody bond from it
/// (`build_sat_bond_from_reward`), publishes it, lays it; the peer fed only blocks seats the SAME custody weight. A free
/// membership seat and a USDm bond seat FINALITY weight and NO custody weight, so no amount of USDm (DB-391's 4 atomic
/// units, or any) reaches the reserve's ≥ 2/3 tally. Re-states lane-harness's `after_a_real_peg_in…` red as the
/// construction that makes its premise false.
#[test]
fn a_sat_bond_built_from_a_mining_reward_seats_custody_weight_on_the_producer_and_the_peer_and_usdm_seats_none() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    // the reward block, folded on both so the reward note is RECORDED on the producer (the bond's membership proof needs it)
    let (_rc_a, dk_a) = wallet_of(&node_a);
    let blk = node_a.produce(5_000, Hash32::hash(b"sat-bond-reward"), Hash32::hash(b"mc")).expect("node_a lays a block");
    let rewards = rewards_in(&blk);
    assert_eq!(rewards.len(), 1);
    let reward_note = reward_note_bytes(&blk, &rewards[0].note_cm().expect("cm"));
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(blk, 5_500), RelayOutcome::Added(_)));
    let _ = node_b.fold_canonical_records();
    assert_eq!(node_a.validators().total_bond(), 0, "PRECONDITION: no custody weight before any SAT bond");
    // the custody bond from that reward, seating a fresh validator key
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let bond = node_a.build_sat_bond_from_reward(&reward_note, &dk_a, &pk, &sk).expect("the operator's wallet bonds its reward in-process");
    assert_eq!(bond.weight, rewards[0].amount, "the whole reward is the weight");
    let stranger = crate::faucet::RecipientSecrets::for_test(&[0x99; 32]);
    assert!(node_a.build_sat_bond_from_reward(&reward_note, &stranger, &pk, &sk).is_none(), "⛔ a stranger's key bonded the operator's reward");
    // ⛔ DB-395: the operator's decapsulation key under spend secrets that are NOT the operator's (what the sealing node could
    // assemble: it can decrypt nothing, but grant it the dk anyway) opens nothing — the commitment binds the operator's spk.
    let forger = crate::faucet::RecipientSecrets { dk: dk_a.dk.clone(), ask: stranger.ask, nk: stranger.nk };
    assert!(node_a.build_sat_bond_from_reward(&reward_note, &forger, &pk, &sk).is_none(), "⛔ the operator's dk without its spend secrets bonded its reward");
    assert!(node_a.publish_sat_bond(&bond).is_ok(), "the producer pools its bond");
    let bonding = node_a.produce(7_000, Hash32::hash(b"sat-bond-lays"), Hash32::hash(b"mc")).expect("the bond block");
    let _ = node_a.fold_canonical_records();
    assert_eq!(node_a.validators().bond_of(&vid), u128::from(bond.weight), "custody weight seated on the producer");
    assert!(matches!(node_b.ingest_block(bonding, 7_500), RelayOutcome::Added(_)), "the peer grafts the bond block");
    let _ = node_b.fold_canonical_records();
    assert_eq!(node_b.validators().bond_of(&vid), u128::from(bond.weight), "⛔ the peer fed only blocks seats the same custody weight");
    assert_eq!(node_b.validators().total_bond(), node_a.validators().total_bond());
    assert_eq!(node_b.validators().finality_weight_of(&vid), u128::from(bond.weight), "a SAT seat votes finality too");
    // the locked note is nobody's balance; the change note (zero here) is recorded
    let locked = bond.locked_cm_bytes().expect("cm");
    assert!(!node_a.holds_record_with_cm(&locked) && !node_b.holds_record_with_cm(&locked), "⛔ the bonded note was recorded as a balance");
    // a USDm-era seat: FINALITY weight, zero custody — DB-391's premise is false by construction
    let (u_pk, _u_sk) = crate::pqauth::ml_dsa_keypair();
    let uvid = crate::pqauth::pubkey_id(&u_pk);
    node_b.validators_mut_for_test().admit_finality(uvid, 4).expect("a finality seat");
    assert_eq!(node_b.validators().bond_of(&uvid), 0, "⛔ DB-391: a non-SAT seat reached custody weight");
    assert_eq!(node_b.validators().finality_weight_of(&uvid), 4);
    assert_eq!(node_b.validators().total_bond(), u128::from(bond.weight), "custody total is SAT only");
}

/// ⛔ ROGUE: a bond whose stated weight is not what its carrier locks, a bond over a USDm-tagged carrier, a bond signed by a
/// key other than the one it seats, and a second seat for the same validator — none seats weight on the peer.
#[test]
fn a_sat_bond_with_a_moved_weight_a_usdm_carrier_a_strangers_signature_or_a_second_seat_seats_nothing_on_the_peer() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let (_rc_a, dk_a) = wallet_of(&node_a);
    let blk = node_a.produce(5_000, Hash32::hash(b"sat-rogue-reward"), Hash32::hash(b"mc")).expect("block");
    let reward_note = reward_note_bytes(&blk, &rewards_in(&blk)[0].note_cm().expect("cm"));
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(blk, 5_500), RelayOutcome::Added(_)));
    let _ = node_b.fold_canonical_records();
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let honest = node_a.build_sat_bond_from_reward(&reward_note, &dk_a, &pk, &sk).expect("builds");
    let v = &crate::pqauth::MlDsaVerifier;
    // ⭐ the weld behind the verified-transition cache: the honest weld verifies, a second ask for the SAME statement is a hit
    // (no verifier run), and every tamper below is a miss — verified in full — and refused
    let runs = crate::verify_cache::runs_on_this_thread;
    assert!(honest.weld_is_authorised(), "CALIBRATION: the honest weld verifies");
    let r0 = runs();
    assert!(honest.weld_is_authorised(), "the honest weld verifies again");
    assert_eq!(runs(), r0, "⛔ a second ask for the same verified weld re-ran the verifier (the cache missed)");
    let refused_in_full = |t: &crate::sat_bond_tx::SatBondTx, what: &str| {
        let before = runs();
        assert!(!t.weld_is_authorised(), "⛔ {what} verified against the weld");
        assert_eq!(runs(), before + 1, "⛔ {what} was answered by the cache instead of the verifier");
    };
    // (i) weight moved by one: the signature covers the weight and the weld covers the weight — both refuse
    let mut moved = honest.clone();
    moved.weight += 1;
    refused_in_full(&moved, "a moved weight");
    refused_in_full(&moved, "a moved weight, asked twice (a refusal is never cached)");
    let mut carrier = honest.clone();
    let mid = carrier.validity_carrier.len() / 2;
    carrier.validity_carrier[mid] ^= 1;
    refused_in_full(&carrier, "a carrier with one flipped byte");
    let mut leaf = honest.clone();
    leaf.leaf_commit[0] ^= 1;
    refused_in_full(&leaf, "a moved leaf commitment");
    let canon = |d: [u64; 4]| crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&d));
    let mut change = honest.clone();
    change.notes[1][..32].copy_from_slice(&canon([21, 22, 23, 24]));
    assert!(change.output_commitments().is_some(), "CALIBRATION: the moved change commitment is a canonical digest");
    refused_in_full(&change, "a moved change commitment");
    let mut spent = honest.clone();
    spent.nullifier = canon([31, 32, 33, 34]);
    assert!(spent.nullifier_digest().is_some(), "CALIBRATION: the moved nullifier is a canonical digest");
    refused_in_full(&spent, "a moved nullifier");
    let mut rebond = honest.clone();
    rebond.rebond = Some(crate::sat_bond_tx::RebondLeg { nullifier_locked: canon([41, 42, 43, 44]), locked_cm: canon([51, 52, 53, 54]) });
    refused_in_full(&rebond, "a first-seat carrier presented as a re-bond");
    assert!(honest.weld_is_authorised(), "the honest weld still verifies after the tampers");
    // (ii) a stranger's signature over the honest statement
    let (s_pk, s_sk) = crate::pqauth::ml_dsa_keypair();
    let mut stranger = honest.clone();
    stranger.sig = crate::pqauth::ml_dsa_sign(&crate::sat_bond_tx::sat_bond_msg(&vid, honest.weight, &honest.locked_cm_bytes().expect("cm"), &honest.nullifier), &s_sk).expect("signs");
    assert!(!stranger.is_authorised(v), "⛔ a stranger's signature seated V's key");
    let mut renamed = honest.clone();
    renamed.vid = crate::pqauth::pubkey_id(&s_pk);
    renamed.pubkey = s_pk.clone();
    assert!(crate::sat_bond_tx::SatBondTx::decode(&renamed.encode()).is_some_and(|t| !t.is_authorised(v)), "⛔ a re-pointed seat verified");
    // (iii) a carrier proved over a USDm-tagged witness, presented as a SAT bond
    let (amount_in, in_owner, _) = dk_a.open_asset(&reward_note).expect("the wallet opens its reward");
    let lanes = usdm_decider::poseidon2_compress::lanes_of;
    let mut w = crate::sat_bond_tx::bond_witness(amount_in, in_owner, amount_in, lanes(&[1, 2, 3, 4]), lanes(&[5, 6, 7, 8]), lanes(&[9, 9, 9, 9]), crate::satoshi::asset_tag()).expect("witness");
    w.asset = usdm_decider::whir_rec_block::USDM_ASSET_TAG;
    let (c_usdm, cms, nf, lc) = usdm_decider::whir_rec_block::prove_asset_bond_validity_carrier_bytes(&w, w.out0_value).expect("proves");
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let mut usdm_bond = honest.clone();
    usdm_bond.validity_carrier = c_usdm;
    usdm_bond.notes[0][..32].copy_from_slice(&b32(cms[0]));
    usdm_bond.notes[1][..32].copy_from_slice(&b32(cms[1]));
    usdm_bond.nullifier = b32(nf);
    usdm_bond.leaf_commit = lc;
    usdm_bond.weight = w.out0_value;
    assert!(!usdm_bond.weld_is_authorised(), "⛔ a USDm-tagged carrier verified as a SAT bond");
    // (iv) the honest bond lands; a SECOND bond for the same validator (a later reward) is refused by the set on both nodes
    assert!(node_a.publish_sat_bond(&honest).is_ok());
    let b1 = node_a.produce(7_000, Hash32::hash(b"sat-rogue-b1"), Hash32::hash(b"mc")).expect("bond block");
    let reward_note2 = reward_note_bytes(&b1, &rewards_in(&b1)[0].note_cm().expect("cm"));
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(b1, 7_500), RelayOutcome::Added(_)));
    let _ = node_b.fold_canonical_records();
    let w1 = node_a.validators().bond_of(&vid);
    assert!(w1 > 0, "CONTROL: the honest bond seated");
    assert_eq!(node_b.validators().bond_of(&vid), w1);
    let second = node_a.build_sat_bond_from_reward(&reward_note2, &dk_a, &pk, &sk).expect("the next reward bonds too");
    // the pool door asks the set's seat rule (2026-10-07: an applied bond never re-enters the pool); a ROGUE producer pools it
    // anyway, and the FOLD refuses it on both nodes
    assert!(node_a.publish_sat_bond(&second).is_err(), "⛔ the pool door admitted a second seat for a seated validator");
    assert!(node_a.pool_sat_bond_past_the_door_for_test(&second).is_ok(), "the rogue pool takes it");
    let b2 = node_a.produce(9_000, Hash32::hash(b"sat-rogue-b2"), Hash32::hash(b"mc")).expect("second bond block");
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(b2, 9_500), RelayOutcome::Added(_)));
    let _ = node_b.fold_canonical_records();
    assert_eq!(node_a.validators().bond_of(&vid), w1, "⛔ a second seat moved the producer's custody weight");
    assert_eq!(node_b.validators().bond_of(&vid), w1, "⛔ a second seat moved the peer's custody weight");
}

/// ⭐ SATOSHI §8.1 — THE WALLET OWNS THE REWARD. The producer seals each reward to its operator wallet's PUBLIC scan key
/// (the node holds no spending key): the wallet's decapsulation key opens the carried note to `(reward_at(key), SAT, sk)`
/// and that `sk` opens the carrier's commitment; a stranger's key opens nothing. The owner clue is the `"sat"` OLI tag at
/// the node's next index — 0, 1, 2 … across blocks, so the wallet's ordinary doubling sweep finds every reward and recovers
/// its index from the tag in ONE step; under any other locator key the tag recovers nothing (no two blocks link to one
/// miner on the wire). The peer fed only blocks records the same note.
#[test]
fn the_reward_is_sealed_to_the_operators_wallet_key_and_its_clue_names_the_next_sat_index() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let (rc_a, dk_a) = wallet_of(&node_a);
    let (rc_b, dk_b) = wallet_of(&node_b);
    assert_ne!(rc_a.scan_ek, rc_b.scan_ek, "two nodes, two wallets");
    let issued_b = node_b.peg().sat_issued();
    let mut credited = 0u64;
    let mut openings: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for (i, seed) in [&b"sat-own-1"[..], b"sat-own-2", b"sat-own-3"].into_iter().enumerate() {
        let blk = node_a.produce(5_000 + 1_000 * i as u64, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays a block");
        let (key, _) = parent_key_of(node_a.dag(), &blk.header.parents).expect("parents held");
        let r = rewards_in(&blk).pop().expect("one reward");
        // DB-393 B4 C3: a fresh seed per reward makes every public opening — and so every commitment — distinct.
        assert!(openings.insert(r.opening), "⛔ two rewards to one recipient carry the same public opening");
        credited += r.amount;
        let note = reward_note_bytes(&blk, &r.note_cm().expect("cm"));
        let (amount, owner, asset) = dk_a.open_asset(&note).expect("the operator's wallet opens its reward");
        assert_eq!((amount, asset), (reward_at(key), crate::satoshi::asset_tag()), "the schedule's amount, denominated in SAT");
        let cm = usdm_decider::whir_rec_block::asset_note_cm(amount, asset, owner.opening());
        assert_eq!(crate::spend_frontier::leaf_to_cm_bytes(cm), r.note_cm().expect("cm"), "the wallet's owner opens the carrier's commitment");
        assert!(dk_b.open_asset(&note).is_none(), "⛔ another wallet's key opened the reward");
        assert_eq!(reward_clue_index(&rc_a.sat_loc_sk, &r.owner_clue), Some(i as u64), "the clue names the next index to its owner");
        assert_eq!(reward_clue_index(&rc_b.sat_loc_sk, &r.owner_clue), None, "⛔ a stranger's locator key recognised the clue");
        let _ = node_a.fold_canonical_records();
        assert!(matches!(node_b.ingest_block(blk, 5_500 + 1_000 * i as u64), RelayOutcome::Added(_)));
        let _ = node_b.fold_canonical_records();
        assert!(node_b.holds_record_with_cm(&r.note_cm().expect("cm")), "the peer fed only blocks records the reward");
    }
    assert_eq!(node_a.reward_recipient().map(|r| r.next_index), Some(3), "three rewards, the counter at 3");
    assert_eq!(node_b.peg().sat_issued() - issued_b, credited, "⛔ DB-393 B4 C3: the peer did not credit every reward to one recipient");
    let clues: std::collections::HashSet<Vec<u8>> = (0..3).map(|j| crate::satoshi::reward_clue(&rc_a.sat_loc_sk, j)).collect();
    assert_eq!(clues.len(), 3, "⛔ two rewards shared a clue (linkable on the wire)");
}

/// A node with NO provisioned recipient lays NO reward (Bitcoin's underclaim) and never a note nobody can spend; its blocks
/// still graft and fold on the peer, and issuance resumes the block after a recipient is installed.
#[test]
fn a_node_without_a_recipient_lays_no_reward_and_its_blocks_still_fold_on_the_peer() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let rc = node_a.reward_recipient().cloned().expect("a test node starts with its wallet's recipient");
    node_a.set_reward_recipient(None);
    let blk = node_a.produce(5_000, Hash32::hash(b"sat-none"), Hash32::hash(b"mc")).expect("a block without a reward");
    assert!(rewards_in(&blk).is_empty(), "⛔ a node with no recipient laid a reward");
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(blk, 5_500), RelayOutcome::Added(_)), "the peer grafts a reward-less block");
    let _ = node_b.fold_canonical_records();
    assert_eq!((node_a.peg().sat_issued(), node_b.peg().sat_issued()), (0, 0), "nothing issued on either node");
    node_a.set_reward_recipient(Some(rc));
    let next = node_a.produce(7_000, Hash32::hash(b"sat-resume"), Hash32::hash(b"mc")).expect("the next block");
    assert_eq!(rewards_in(&next).len(), 1, "CONTROL: issuance resumes once a recipient is installed");
}

/// ⭐ SATOSHI §8.2 — the provisioning door's file half (`provision_reward_recipient_at`): installs `(ek, loc, from_index)`;
/// the SAME recipient re-provisioned keeps its counter and moves it only FORWARD (no locator is ever reused after a node
/// rebuild); a DIFFERENT ek replaces; a malformed or wrong-width key is refused and the file is untouched.
#[test]
fn provisioning_the_reward_recipient_moves_the_counter_only_forward_and_refuses_a_malformed_key() {
    use crate::satoshi::{load_reward_recipient_at, provision_reward_recipient_at};
    let dir = std::env::temp_dir().join(format!("sat-recipient-pin-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("validator-1.reward");
    let _ = std::fs::remove_file(&path);
    let (rc, _dk) = RewardRecipient::for_test(&[1u8; 32]);
    let (other, _dk2) = RewardRecipient::for_test(&[2u8; 32]);
    assert!(load_reward_recipient_at(&path).is_none(), "PRECONDITION: no file");
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let (spk, other_spk) = (b32(rc.spk), b32(other.spk));
    let installed = provision_reward_recipient_at(&path, &rc.scan_ek, &spk, rc.sat_loc_sk, 5).expect("installs");
    assert_eq!((installed.scan_ek.clone(), installed.spk, installed.next_index), (rc.scan_ek.clone(), rc.spk, 5));
    // DB-395: the written form carries the spend key — the on-disk bytes round-trip it exactly.
    assert_eq!(RewardRecipient::decode(&installed.encode()).map(|r| r.spk), Some(rc.spk), "⛔ the spend key did not round-trip");
    assert_eq!(load_reward_recipient_at(&path).map(|r| r.next_index), Some(5), "persisted");
    let again = provision_reward_recipient_at(&path, &rc.scan_ek, &spk, rc.sat_loc_sk, 3).expect("re-provisions");
    assert_eq!(again.next_index, 5, "⛔ the counter moved BACKWARD (a reused locator links two rewards)");
    let forward = provision_reward_recipient_at(&path, &rc.scan_ek, &spk, rc.sat_loc_sk, 9).expect("re-provisions");
    assert_eq!(forward.next_index, 9, "the wallet's higher mark moves it forward");
    assert_eq!(provision_reward_recipient_at(&path, &other.scan_ek[..1183], &other_spk, other.sat_loc_sk, 0), Err("REWARD_RECIPIENT_KEY_MALFORMED"), "⛔ a wrong-width key installed");
    assert_eq!(provision_reward_recipient_at(&path, &[0xFFu8; 1184], &other_spk, other.sat_loc_sk, 0), Err("REWARD_RECIPIENT_KEY_MALFORMED"), "⛔ a key that is not an ML-KEM key installed");
    // ⛔ DB-395: a spend key that is not a canonical digest is refused — the node never seals to a key it had to reduce.
    assert_eq!(provision_reward_recipient_at(&path, &other.scan_ek, &[0xFFu8; 32], other.sat_loc_sk, 0), Err("REWARD_RECIPIENT_SPEND_KEY_MALFORMED"), "⛔ a non-canonical spend key installed");
    assert_eq!(load_reward_recipient_at(&path).map(|r| (r.scan_ek, r.next_index)), Some((rc.scan_ek.clone(), 9)), "a refusal leaves the file as it was");
    let replaced = provision_reward_recipient_at(&path, &other.scan_ek, &other_spk, other.sat_loc_sk, 0).expect("a new wallet replaces");
    assert_eq!((replaced.scan_ek, replaced.next_index), (other.scan_ek.clone(), 0), "a different wallet starts its own index space");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lay one honest block on `node_a`, fold it, graft + fold it on `node_b`; return its reward note's whole bytes.
fn mine_and_share(node_a: &mut Node, node_b: &mut Node, ts: u64, seed: &[u8]) -> Vec<u8> {
    let blk = node_a.produce(ts, Hash32::hash(seed), Hash32::hash(b"mc")).expect("node_a lays a block");
    let note = reward_note_bytes(&blk, &rewards_in(&blk)[0].note_cm().expect("cm"));
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(blk, ts + 500), RelayOutcome::Added(_)), "the peer grafts");
    let _ = node_b.fold_canonical_records();
    note
}
/// Pool `t` on `node_a`, lay it, fold, graft + fold on `node_b`.
fn bond_and_share(node_a: &mut Node, node_b: &mut Node, t: &crate::sat_bond_tx::SatBondTx, ts: u64, seed: &[u8]) {
    assert!(node_a.publish_sat_bond(t).is_ok(), "the producer pools the bond");
    let blk = node_a.produce(ts, Hash32::hash(seed), Hash32::hash(b"mc")).expect("the bond block");
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(blk, ts + 500), RelayOutcome::Added(_)), "the peer grafts the bond block");
    let _ = node_b.fold_canonical_records();
}

/// ⛔⛔ ORDER — A SAT BOND THAT FOLDS BEFORE ITS VALIDATOR'S FREE MEMBERSHIP SEAT STILL LETS THAT SEAT REGISTER THE CUSTODY
/// POINT, on the producer and on a peer fed only blocks, so the custody weight reaches the reserve's custody leaf. The set is
/// a function of the objects the chain carries, never of their fold order (Kaspa / Ethereum STF). MEASURED 2026-10-09
/// (db249, db286: "seated 2, custody-weighted with a registered point 0, custody leaf members 0"): the seat door read the
/// SAT seat's finality weight as "already seated", so the seat's point never registered and the weight custodied nothing.
#[test]
fn a_sat_bond_folded_before_its_membership_seat_still_lets_the_seat_register_the_custody_point_on_the_producer_and_the_peer() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let (_rc_a, dk_a) = wallet_of(&node_a);
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    // the SAT bond first: custody weight, no point
    let reward = mine_and_share(&mut node_a, &mut node_b, 5_000, b"order-reward");
    let bond = node_a.build_sat_bond_from_reward(&reward, &dk_a, &pk, &sk).expect("the operator's wallet bonds its reward");
    bond_and_share(&mut node_a, &mut node_b, &bond, 7_000, b"order-bond");
    for n in [&node_a, &node_b] {
        assert_eq!(n.validators().bond_of(&vid), u128::from(bond.weight), "PRECONDITION: the SAT seat holds custody weight");
        assert!(!n.validators().holds_finality_seat(&vid), "PRECONDITION: no membership seat yet");
        assert!(n.custody_members_current().is_empty(), "PRECONDITION: no registered point, so no custody leaf member");
    }
    // then the free membership seat for the SAME key, laid and folded on the producer, grafted and folded on the peer
    let (kem_ek, _kem_dk) = crate::pqkem::keypair();
    let header = crate::membership_bond_tx::MembershipBondHeader {
        secp33: vec![2u8; 33],
        ed32: [9u8; 32],
        kem_ek,
        nonce: crate::membership_bond_tx::fresh_seat_nonce(),
    };
    let sig = crate::pqauth::ml_dsa_sign(&crate::pqauth::validator_membership_msg(&vid, &header.digest()), &sk).expect("signs");
    assert_eq!(node_a.publish_membership_bond(&pk, &sig, header), crate::node::AssetSpendOutcome::Published, "a founding slot is open");
    let seat_blk = node_a.produce(9_000, Hash32::hash(b"order-seat"), Hash32::hash(b"mc")).expect("the seat block");
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(seat_blk, 9_500), RelayOutcome::Added(_)), "the peer grafts the seat block");
    let _ = node_b.fold_canonical_records();
    for (n, who) in [(&node_a, "the producer"), (&node_b, "the peer fed only blocks")] {
        assert!(
            n.validators().holds_finality_seat(&vid),
            "⛔ ORDER: on {who} the membership seat was read as already seated because the SAT seat votes finality"
        );
        assert_eq!(
            n.custody_members_current(),
            vec![([2u8; 32], u128::from(bond.weight))], // the seat header's x-only point (secp33[1..]) at the SAT weight
            "⛔ ORDER: on {who} the custody point never registered, so the SAT weight custodies nothing"
        );
    }
    assert_eq!(node_a.validators().finality_weight_of(&vid), node_b.validators().finality_weight_of(&vid));
    // CALIBRATION: the same seat request re-carried seats nothing more (the seat's own one-shot right + AlreadySeated)
    let weight_after = node_b.validators().total_finality_weight();
    let again = node_a.produce(11_000, Hash32::hash(b"order-again"), Hash32::hash(b"mc")).expect("a later block");
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(again, 11_500), RelayOutcome::Added(_)));
    let _ = node_b.fold_canonical_records();
    assert_eq!(node_b.validators().total_finality_weight(), weight_after, "a later block seats nothing more");
}

/// ⛔⛔ SATOSHI §9.2 — A SAT BOND'S LOCKED NOTE IS HELD WHOLE on the producer and on the peer, so the unbond that returns it
/// returns a SPENDABLE note: it scans under the bonder's key to exactly the weight in SAT. MEASURED by reading 2026-10-05: the
/// carriage arm reduced BOTH notes to 64-byte references while only the change rides `output_notes`, and the fold applies the
/// carriage form — every node locked 64 bytes.
#[test]
fn a_sat_bonds_locked_note_is_held_whole_on_the_producer_and_the_peer_so_an_unbond_returns_a_spendable_note() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let (_rc, dk) = wallet_of(&node_a);
    let reward = mine_and_share(&mut node_a, &mut node_b, 5_000, b"sat-whole-1");
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let bond = node_a.build_sat_bond_from_reward(&reward, &dk, &pk, &sk).expect("builds");
    bond_and_share(&mut node_a, &mut node_b, &bond, 7_000, b"sat-whole-bond");
    for (who, n) in [("producer", &node_a), ("peer", &node_b)] {
        let held = n.bond_locked_note(&vid).expect("the locked note is held").to_vec();
        assert_eq!(held.len(), crate::cover::PQ_NOTE_BYTES, "⛔ the {who} locked a {}-byte reference, not the note", held.len());
        let (amount, _sk, asset) = dk.open_asset(&held).expect("the bonder's key opens the locked note");
        assert_eq!((amount, asset), (bond.weight, crate::satoshi::asset_tag()), "the {who}'s locked note is the weight in SAT");
    }
}

/// ⛔⛔⛔ A SAT BOND WHOSE FOLD STEP IS REFUSED AND RETRIED, ON A PEER THAT FOLDS IT AT A LATER TIP, SEATS ONCE AND HOLDS THE
/// PRODUCER'S STATE — the seat, the change note in the record, the bonded input spent, the lock height and every anchor-ring
/// root. MEASURED sim-20261007-043933 (fast journey T3): a fold step is retried whenever its record has not arrived; the
/// retry met its own first attempt's seat (`AlreadyBonded` — the objects step's unwind restores the peg ledger only),
/// stripped the change note and left the input unadmitted ON THAT NODE (member ring split at ordinal 744, the input
/// re-carried 79 times), and the lock height was each node's own tip, so the unbond matured on n2 alone ([4000000, 4000000,
/// 0]). The peer here meets the record late (the production fetch path brings it) and folds after a later block landed.
#[test]
fn a_sat_bond_folded_by_a_retried_step_at_a_later_tip_seats_once_with_the_producers_state() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    // the peer folds one block below its tip (production folds `record_fold_depth` below), so the bond block folds only when
    // the next block lands — after its record was taken away
    let mut node_b = crate::node::tests::testnet_party_with_fold_depth(1);
    let (_rc, dk) = wallet_of(&node_a);
    let reward = mine_and_share(&mut node_a, &mut node_b, 5_000, b"sat-retry-1");
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let bond = node_a.build_sat_bond_from_reward(&reward, &dk, &pk, &sk).expect("builds");
    assert!(node_a.publish_sat_bond(&bond).is_ok(), "the producer pools the bond");
    let blk = node_a.produce(7_000, Hash32::hash(b"sat-retry-bond"), Hash32::hash(b"mc")).expect("the bond block");
    let bid = blk.id();
    let _ = node_a.fold_canonical_records();
    // a later block on top: the peer folds the bond block at a LATER tip than the producer did
    let next = node_a.produce(8_000, Hash32::hash(b"sat-retry-next"), Hash32::hash(b"mc")).expect("the next block");
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(blk, 7_500), RelayOutcome::Added(_)), "the peer grafts the bond block");
    assert!(!node_b.block_record_folded_for_test(&bid), "PRECONDITION: one block below nothing, the bond block waits to fold");
    assert!(node_b.withhold_block_record_for_test(&bid), "PRECONDITION: the peer held the bond block's record");
    assert!(matches!(node_b.ingest_block(next, 8_500), RelayOutcome::Added(_)), "the peer grafts the next block");
    let _ = node_b.fold_canonical_records(); // the step runs its objects and bond steps, then the record fold refuses
    assert!(!node_b.block_record_folded_for_test(&bid), "PRECONDITION: the bond block's first fold was refused");
    assert!(node_b.deliver_wanted_records_for_test(&node_a) > 0, "the fold wants the record and the producer serves it");
    let _ = node_b.fold_canonical_records(); // the RETRY
    assert!(node_b.block_record_folded_for_test(&bid), "the retried step placed the bond block");
    let change: [u8; 32] = bond.notes[1][..32].try_into().expect("a note opens with its commitment");
    for (who, n) in [("producer", &node_a), ("peer", &node_b)] {
        assert_eq!(n.validators().bond_of(&vid), u128::from(bond.weight), "⛔ the {who} did not seat the bond's weight");
        assert!(n.holds_record_with_cm(&change), "⛔ the {who}'s record lost the bond's change note");
        assert!(n.fold_point_spent_set().holds(&bond.nullifier), "⛔ the {who} left the bonded input unspent");
    }
    assert!(node_a.unbond_matures_at(&vid).is_some(), "CONTROL: a SAT seat locks its note, so its unbond has a maturity");
    assert_eq!(
        node_b.unbond_matures_at(&vid),
        node_a.unbond_matures_at(&vid),
        "⛔ the lock height is each node's own tip at its fold, not the carrying block's"
    );
    let ring = |n: &Node| n.anchor_ring().into_iter().collect::<std::collections::HashMap<u64, crate::spend_frontier::Digest4>>();
    let (ra, rb) = (ring(&node_a), ring(&node_b));
    let mut common: Vec<u64> = ra.keys().filter(|o| rb.contains_key(o)).copied().collect();
    common.sort_unstable();
    assert!(!common.is_empty(), "CONTROL: both nodes hold anchor-ring roots");
    let split: Vec<u64> = common.iter().copied().filter(|o| ra[o] != rb[o]).collect();
    assert!(split.is_empty(), "⛔ the member ring holds two roots at fold ordinal(s) {split:?} of {common:?}");
}

/// ⭐ SATOSHI §9 — RE-BOND: a seated validator consumes a fresh SAT note AND its locked note into ONE new locked note; the
/// producer and the peer fed only blocks both seat the SUM as custody weight, hold the new note whole (it opens to the sum),
/// and retire the old locked note's nullifier in the spent set — so the old note can never be returned or re-bonded.
#[test]
fn a_rebond_grows_custody_weight_to_the_sum_on_the_producer_and_the_peer_and_retires_the_old_locked_note() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let (_rc, dk) = wallet_of(&node_a);
    let r1 = mine_and_share(&mut node_a, &mut node_b, 5_000, b"sat-rb-1");
    let r2 = mine_and_share(&mut node_a, &mut node_b, 6_000, b"sat-rb-2");
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let first = node_a.build_sat_bond_from_reward(&r1, &dk, &pk, &sk).expect("first seat");
    bond_and_share(&mut node_a, &mut node_b, &first, 8_000, b"sat-rb-seat");
    let w1 = node_a.validators().bond_of(&vid);
    assert_eq!((w1, node_b.validators().bond_of(&vid)), (u128::from(first.weight), u128::from(first.weight)), "CONTROL: the first seat on both nodes");
    let locked = node_a.bond_locked_note(&vid).expect("locked").to_vec();
    let rebond = node_a.build_sat_rebond_in_process(&r2, &locked, &dk, &pk, &sk).expect("the re-bond builds");
    let leg = rebond.rebond.clone().expect("a re-bond names its locked input");
    let (v2, _, _) = dk.open_asset(&r2).expect("r2 opens");
    assert_eq!(rebond.weight, first.weight + v2, "the new weight is the sum");
    bond_and_share(&mut node_a, &mut node_b, &rebond, 10_000, b"sat-rb-grow");
    for (who, n) in [("producer", &node_a), ("peer", &node_b)] {
        assert_eq!(n.validators().bond_of(&vid), u128::from(rebond.weight), "⛔ the {who} did not seat the summed custody weight");
        assert_eq!(n.validators().total_bond(), u128::from(rebond.weight), "the {who}'s custody total is the one seat's new weight (no double count)");
        let held = n.bond_locked_note(&vid).expect("locked").to_vec();
        assert_eq!(held.len(), crate::cover::PQ_NOTE_BYTES);
        assert_eq!(dk.open_asset(&held).map(|x| x.0), Some(rebond.weight), "the {who} holds the NEW locked note");
        assert!(n.fold_point_spent_set().holds(&leg.nullifier_locked), "⛔ the {who} did not retire the old locked note");
        assert!(!n.holds_record_with_cm(&rebond.locked_cm_bytes().expect("cm")), "⛔ the {who} recorded the new locked note as a balance");
        // §9.3 R5 — the weight semantics, stated: a re-bond raises CUSTODY weight; finality weight counts the custody seat, so
        // it follows (a SAT seat votes finality too, `finality_weight_of = custody + finality seat`).
        assert_eq!(n.validators().finality_weight_of(&vid), u128::from(rebond.weight), "the {who}'s finality weight follows the custody seat");
    }
}

/// ⛔⛔⛔ §9.3 R1 (lane-harness, CRITICAL) — A RE-BOND CANNOT EXIT THE BOND. Consuming the locked note (the seated weight) with
/// a fresh note into a LOWER weight would hand the locked value back as change at once: no unbond, no window, nothing for a
/// slash to burn. CALIBRATION: the lowering carrier and its signature are HONEST (the weld verifies), so the only thing
/// refusing it is the raise rule — at the admit door, at the fold door, and at the set. The peer, fed the block a rogue lays,
/// keeps the old weight and the old locked note.
#[test]
fn a_rebond_that_lowers_custody_weight_is_refused_at_every_door_and_the_old_weight_stays_seated() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let (_rc, dk) = wallet_of(&node_a);
    let r1 = mine_and_share(&mut node_a, &mut node_b, 5_000, b"sat-r1-1");
    let r2 = mine_and_share(&mut node_a, &mut node_b, 6_000, b"sat-r1-2");
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let first = node_a.build_sat_bond_from_reward(&r1, &dk, &pk, &sk).expect("first seat");
    bond_and_share(&mut node_a, &mut node_b, &first, 8_000, b"sat-r1-seat");
    let w1 = node_b.validators().bond_of(&vid);
    let locked = node_a.bond_locked_note(&vid).expect("locked").to_vec();
    let exit = node_a.build_sat_rebond_with_weight_for_test(&r2, &locked, &dk, &pk, &sk, 1).expect("the exit carrier builds (conservation holds)");
    assert!(exit.weld_is_authorised() && exit.is_authorised(&crate::pqauth::MlDsaVerifier), "CALIBRATION: the lowering re-bond's carrier and signature are honest");
    let why = Some("a re-bond must raise the custody weight (its change can come only from the fresh note)");
    assert_eq!(crate::node::objects::sat_bond_tx::sat_bond_refusal(&node_a, &exit, crate::respend::MemberDoor::Admit), why, "⛔ ADMIT: a re-bond lowered custody weight");
    assert_eq!(crate::node::objects::sat_bond_tx::sat_bond_refusal(&node_b, &exit, crate::respend::MemberDoor::Fold), why, "⛔ FOLD (peer): a re-bond lowered custody weight");
    let same = node_a.build_sat_rebond_with_weight_for_test(&r2, &locked, &dk, &pk, &sk, first.weight).expect("an equal-weight re-bond builds");
    assert_eq!(crate::node::objects::sat_bond_tx::sat_bond_refusal(&node_a, &same, crate::respend::MemberDoor::Admit), why, "an equal weight adds nothing and is refused too");
    assert!(node_b.validators_mut_for_test().rebond_custody(vid, w1 - 1).is_err(), "⛔ SET: the custody weight was lowered");
    assert_eq!(node_b.validators().bond_of(&vid), w1, "the peer keeps the old weight");
    assert_eq!(node_b.bond_locked_note(&vid).map(<[u8]>::to_vec), Some(locked), "the peer keeps the old locked note");
}

/// ⛔ §9.3 R2 — a SLASHED validator cannot re-bond: the slash removes its custody seat (the door refuses "no custody seat")
/// and marks it slashed (the set refuses `Slashed`). Its locked note stays as dead state and its unbond returns nothing.
#[test]
fn a_slashed_validator_cannot_rebond_by_either_door_and_its_unbond_returns_nothing() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let (_rc, dk) = wallet_of(&node_a);
    let r1 = mine_and_share(&mut node_a, &mut node_b, 5_000, b"sat-r2-1");
    let r2 = mine_and_share(&mut node_a, &mut node_b, 6_000, b"sat-r2-2");
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let first = node_a.build_sat_bond_from_reward(&r1, &dk, &pk, &sk).expect("first seat");
    bond_and_share(&mut node_a, &mut node_b, &first, 8_000, b"sat-r2-seat");
    let locked = node_a.bond_locked_note(&vid).expect("locked").to_vec();
    let rebond = node_a.build_sat_rebond_in_process(&r2, &locked, &dk, &pk, &sk).expect("builds");
    assert_eq!(crate::node::objects::sat_bond_tx::sat_bond_refusal(&node_a, &rebond, crate::respend::MemberDoor::Admit), None, "CONTROL: before the slash the re-bond is admissible");
    assert!(node_a.apply_slash(vid).is_some(), "the slash burns the seat");
    assert_eq!(crate::node::objects::sat_bond_tx::sat_bond_refusal(&node_a, &rebond, crate::respend::MemberDoor::Admit), Some("a re-bond names a validator with no custody seat"), "⛔ a slashed validator's re-bond passed the door");
    assert!(matches!(node_a.validators_mut_for_test().rebond_custody(vid, u128::from(rebond.weight)), Err(crate::validator::ValidatorError::Slashed)), "⛔ the set re-seated a slashed validator");
    assert_eq!(node_a.validators().bond_of(&vid), 0, "nothing seated");
    assert_eq!(node_a.apply_unbond_release(vid, vec![7u8; 8], u64::MAX / 2, u64::MAX / 2), None, "⛔ a slashed validator's unbond returned its burned note");
}

/// ⛔ §9.3 R3 (DB-385's rule) — A STRANGER-SIGNED COPY OF V's RE-BOND OWNS NOTHING: it justifies neither V's fresh nullifier
/// nor V's LOCKED nullifier into any lane (the one site every reader shares), so a producer that saw V's pooled re-bond cannot
/// burn V's locked note's key; V's own signed re-bond owns both. (The peer-level rogue-block cell is lane-harness's census.)
#[test]
fn a_stranger_signed_rebond_owns_no_nullifier_and_vs_own_owns_both() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let (_rc, dk) = wallet_of(&node_a);
    let r1 = mine_and_share(&mut node_a, &mut node_b, 5_000, b"sat-r3-1");
    let r2 = mine_and_share(&mut node_a, &mut node_b, 6_000, b"sat-r3-2");
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let first = node_a.build_sat_bond_from_reward(&r1, &dk, &pk, &sk).expect("first seat");
    bond_and_share(&mut node_a, &mut node_b, &first, 8_000, b"sat-r3-seat");
    let locked = node_a.bond_locked_note(&crate::pqauth::pubkey_id(&pk)).expect("locked").to_vec();
    let honest = node_a.build_sat_rebond_in_process(&r2, &locked, &dk, &pk, &sk).expect("builds");
    let leg = honest.rebond.clone().expect("leg");
    assert_eq!(crate::chain_object::object_own_nullifiers(&honest.to_object()), Some(vec![honest.nullifier, leg.nullifier_locked]), "V's re-bond owns both inputs");
    let (_s_pk, s_sk) = crate::pqauth::ml_dsa_keypair();
    let mut forged = honest.clone();
    forged.sig = crate::pqauth::ml_dsa_sign(&honest.statement().expect("stmt"), &s_sk).expect("signs");
    assert_eq!(crate::chain_object::object_own_nullifiers(&forged.to_object()), None, "⛔ a stranger-signed re-bond owned V's nullifiers");
    assert!(!crate::chain_object::admissible(&forged.to_object(), 0, u64::MAX, false), "⛔ the admission door took a stranger-signed re-bond");
}


/// ⛔⛔ SATOSHI §9 — every re-bond tamper seats nothing: a PHANTOM locked input (the carrier opened a note that is not the
/// validator's locked note), a stated locked commitment that the carrier did not open, a re-bond by a key with no custody
/// seat, a stranger's signature, the leg stripped (the re-bond carrier under the single-seat verifier), and a REPLAY of a
/// re-bond that already applied (its locked nullifier is in the spent set).
#[test]
fn a_rebond_with_a_phantom_locked_input_an_unseated_key_a_strangers_signature_a_stripped_leg_or_a_replay_seats_nothing() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let (_rc, dk) = wallet_of(&node_a);
    let r1 = mine_and_share(&mut node_a, &mut node_b, 5_000, b"sat-rbt-1");
    let r2 = mine_and_share(&mut node_a, &mut node_b, 6_000, b"sat-rbt-2");
    let r3 = mine_and_share(&mut node_a, &mut node_b, 7_000, b"sat-rbt-3");
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let v = &crate::pqauth::MlDsaVerifier;
    let first = node_a.build_sat_bond_from_reward(&r1, &dk, &pk, &sk).expect("first seat");
    // an UNSEATED key cannot re-bond: build a re-bond with r1 as the "locked" note before any seat exists
    let (u_pk, u_sk) = crate::pqauth::ml_dsa_keypair();
    let unseated = node_a.build_sat_rebond_in_process(&r2, &r1, &dk, &u_pk, &u_sk).expect("builds (the carrier is honest)");
    assert_eq!(crate::node::objects::sat_bond_tx::sat_bond_refusal(&node_a, &unseated, crate::respend::MemberDoor::Admit), Some("a re-bond names a validator with no custody seat"));
    bond_and_share(&mut node_a, &mut node_b, &first, 9_000, b"sat-rbt-seat");
    let w1 = node_b.validators().bond_of(&vid);
    assert!(w1 > 0, "CONTROL: seated");
    let locked = node_a.bond_locked_note(&vid).expect("locked").to_vec();
    // PHANTOM: the carrier consumes r3 as its "locked" input (a real SAT note the wallet owns, but NOT the locked one)
    let phantom = node_a.build_sat_rebond_in_process(&r2, &r3, &dk, &pk, &sk).expect("builds (the carrier is honest about r3)");
    assert!(phantom.weld_is_authorised() && phantom.is_authorised(v), "CALIBRATION: the phantom's carrier and signature are honest");
    assert_eq!(crate::node::objects::sat_bond_tx::sat_bond_refusal(&node_a, &phantom, crate::respend::MemberDoor::Admit), Some("the re-bond's locked input is not this validator's locked note"), "⛔ a phantom locked input passed the set check");
    // a STATED locked cm the carrier did not open: the leg names the real locked note, the carrier opened r3
    let mut lied = phantom.clone();
    lied.rebond = Some(crate::sat_bond_tx::RebondLeg { nullifier_locked: phantom.rebond.clone().expect("leg").nullifier_locked, locked_cm: <[u8; 32]>::try_from(&locked[..32]).expect("cm") });
    assert!(!lied.weld_is_authorised(), "⛔ the carrier verified against a locked note it did not open");
    // the honest re-bond, then the tampers on it
    let honest = node_a.build_sat_rebond_in_process(&r2, &locked, &dk, &pk, &sk).expect("the honest re-bond");
    let (s_pk, s_sk) = crate::pqauth::ml_dsa_keypair();
    let mut stranger = honest.clone();
    stranger.sig = crate::pqauth::ml_dsa_sign(&honest.statement().expect("stmt"), &s_sk).expect("signs");
    assert!(!stranger.is_authorised(v), "⛔ a stranger's signature authorised V's re-bond");
    let _ = s_pk;
    let mut stripped = honest.clone();
    stripped.rebond = None;
    assert!(!stripped.weld_is_authorised(), "⛔ a re-bond carrier verified as a first seat (leg stripped)");
    assert!(!stripped.is_authorised(v), "⛔ a re-bond signature authorised a first-seat statement");
    bond_and_share(&mut node_a, &mut node_b, &honest, 11_000, b"sat-rbt-grow");
    let w2 = node_b.validators().bond_of(&vid);
    assert_eq!(w2, u128::from(honest.weight), "CONTROL: the honest re-bond seats the sum on the peer");
    // REPLAY: the same re-bond again — its locked nullifier is spent and the set's locked note is the new one
    let why = crate::node::objects::sat_bond_tx::sat_bond_refusal(&node_a, &honest, crate::respend::MemberDoor::Admit);
    assert!(why.is_some(), "⛔ a replayed re-bond passed admission");
    assert_eq!((node_a.validators().bond_of(&vid), node_b.validators().bond_of(&vid)), (w2, w2), "nothing moved");
}

/// ⛔⛔ SATOSHI — A REWARD-ONLY BLOCK CROSSES THE WIRE COMPLETE. `output_notes` never rides the wire (DB-165), so the reward
/// note travels whole in the credit set and the receiver's ONE rehydration door rebuilds the body itself: the peer fed only
/// the wire form records the reward at graft (no record-lane ask, no payload gap) and its fold issues exactly what the
/// producer's did. MEASURED before (lane-harness netsim, 2026-10-05): with the reward as a reference every receiver held
/// every block without data — record-serve time ~4,000×, relay past the 4 s floor, a forked mesh.
#[test]
fn a_reward_only_block_received_in_wire_form_records_its_reward_locally_and_folds_like_the_producer() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let blk = node_a.produce(5_000, Hash32::hash(b"sat-wire-1"), Hash32::hash(b"mc")).expect("node_a lays a block");
    let r = rewards_in(&blk).pop().expect("one reward");
    assert_eq!(r.note.len(), crate::cover::PQ_NOTE_BYTES, "⛔ the reward rides the credit set as a reference, not whole");
    // §22/§22b: the node-to-node wire form is the gossip ENVELOPE (`postcard(Block) ‖ σ ‖ wide objects`) — the cover key that
    // opens the sealed credit set and the wide bytes its references name travel beside the hashed block, never inside it.
    let wire: Block = crate::block::gossip_decode(&crate::block::gossip_encode(&blk)).expect("the envelope decodes");
    assert!(wire.output_notes.is_empty(), "CALIBRATION: the wire form carries no `output_notes` (DB-165)");
    let _ = node_a.fold_canonical_records();
    let rid = node_a.record_addr_for_block(&blk.id()).expect("the producer records its block");
    assert!(matches!(node_b.ingest_block(wire, 5_500), RelayOutcome::Added(_)), "the peer grafts the wire block");
    let cm = r.note_cm().expect("cm");
    // RE-FIXTURED 2026-10-28 (lane funds, §22): the node-to-node wire form is the gossip envelope, which carries the block's cover
    // key — and a quiet block's §RF-3 §14 seed note is a function of that key (`cover::seed_note_for_key`), so the peer rebuilds
    // the record from the block alone, with no record-lane round trip (before §22 the seed rode the record lane only and the peer
    // owed the record: the 2026-10-27 fixture). The record the peer derives must be the producer's own: its served reals are
    // the ones the peer now holds.
    assert!(node_b.holds_record_with_cm(&cm), "⛔ the envelope carries the key: the peer records the reward from the block alone");
    let served = node_a.da_record_reals(rid).expect("the producer serves its record").concat();
    let peer = node_b.da_record_reals(rid).expect("the peer holds the record at the producer's address").concat();
    assert_eq!(peer, served, "⛔ the peer's derived record differs from the producer's");
    let _ = node_b.fold_canonical_records();
    assert_eq!(node_b.peg().sat_issued(), node_a.peg().sat_issued(), "the peer's fold issued exactly what the producer's did");
    assert!(node_b.peg().sat_issued() > 0, "CONTROL: something was issued");
}

/// ⭐ SATOSHI — SAT IS SPENDABLE: the operator's wallet sends its mining reward to another wallet through the asset transfer door
/// (`Class::AssetSpend`, the SAME door the wallet's `wallet_send_sat` posts to): output 0 sealed to the recipient's key, output 1
/// the change. The peer fed only blocks records the recipient's note; the recipient's key opens it to exactly the amount in SAT;
/// the reward note is spent (its nullifier in the peer's spent set). CONTROL: a transfer whose carrier is corrupted is refused
/// at the door before it is pooled.
#[test]
fn a_mining_reward_sent_through_the_asset_transfer_door_credits_the_recipient_in_sat_on_a_peer_fed_only_blocks() {
    use usdm_decider::whir_rec_block::{asset_note_cm, prove_asset_spend_validity_carrier_bytes, AssetSpendValidityWitness};
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let (_rc, dk) = wallet_of(&node_a);
    let reward = mine_and_share(&mut node_a, &mut node_b, 5_000, b"sat-send-1");
    let (value_in, in_owner, tag) = dk.open_asset(&reward).expect("the operator's wallet opens its reward");
    let (recipient, _) = RewardRecipient::for_test(&[0x5e; 32]);
    let recipient_wallet = crate::faucet::RecipientSecrets::for_test(&[0x5e; 32]);
    let amount = value_in / 3;
    // DB-395: each output sealed to its owner's ADDRESS (ek + spk) — the sender holds only the openings.
    let (to_note, to_opening) = crate::faucet::seal_asset_note(&recipient.scan_ek, &recipient.spk, amount, tag, Some([1u8; 32])).expect("seal to the recipient");
    let own = wallet_of(&node_a).0;
    let (ch_note, ch_opening) = crate::faucet::seal_asset_note(&own.scan_ek, &own.spk, value_in - amount, tag, Some([2u8; 32])).expect("seal change");
    let lc_blind = usdm_decider::poseidon2_compress::lanes_of(&[7, 7, 7, 7]);
    let w = AssetSpendValidityWitness {
        value_in,
        owner: in_owner,
        value_out: value_in,
        fee: 0,
        lc_blind,
        out0_value: amount,
        out0_opening: to_opening,
        out1_value: value_in - amount,
        out1_opening: ch_opening,
        asset: tag,
    };
    let (carrier, cms, nf, lc) = prove_asset_spend_validity_carrier_bytes(&w).expect("the transfer proves");
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    assert_eq!((&to_note[..32], &ch_note[..32]), (&b32(cms[0])[..], &b32(cms[1])[..]), "the sealed notes are the carrier's outputs");
    let reward_leaf = asset_note_cm(value_in, tag, in_owner.opening());
    let reward_cm = b32(reward_leaf);
    let (membership_carrier, tip_prev, tip_root, tip_acc, named_record) =
        node_a.own_note_membership_one_step(&reward_cm, reward_leaf, nf, lc_blind).expect("membership of the reward");
    let clue = |j: u64| crate::satoshi::reward_clue(&[0x77; 32], j);
    let t = crate::asset_tx::AssetSpendTx {
        notes: [to_note.to_vec(), ch_note.to_vec()],
        nullifier: b32(nf),
        leaf_commit: lc,
        validity_carrier: carrier,
        membership_carrier,
        member_tuple: Vec::new(),
        named_record,
        tip_prev,
        tip_root,
        tip_acc,
        owner_clues: vec![clue(0), clue(1)],
        slot_tag: None,
    };
    let mut broken = t.clone();
    let mid = broken.validity_carrier.len() / 2;
    broken.validity_carrier[mid] ^= 1;
    assert!(!matches!(node_a.execute_asset_spend(&broken), crate::node::AssetSpendOutcome::Published), "⛔ a corrupted transfer carrier was pooled");
    assert_eq!(node_a.execute_asset_spend(&t), crate::node::AssetSpendOutcome::Published, "the SAT transfer is admitted to the pool");
    let blk = node_a.produce(7_000, Hash32::hash(b"sat-send-blk"), Hash32::hash(b"mc")).expect("the transfer block");
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(blk, 7_500), RelayOutcome::Added(_)), "the peer grafts the transfer block");
    let _ = node_b.fold_canonical_records();
    for (who, n) in [("producer", &node_a), ("peer", &node_b)] {
        assert!(n.holds_record_with_cm(&b32(cms[0])), "⛔ the {who} did not credit the recipient's SAT note");
        assert!(n.fold_point_spent_set().holds(&b32(nf)), "⛔ the {who} did not spend the reward note");
    }
    let (got, _, got_tag) = recipient_wallet.open_asset(&to_note).expect("the recipient opens the note");
    assert_eq!((got, got_tag), (amount, crate::satoshi::asset_tag()), "the recipient holds exactly the amount, in SAT");
}

/// A local accept-all decider verifier for the adopt WIRING (the real WHIR verify is pinned in `crate::whir_decider`).
struct AcceptAllDecider;
impl crate::decider::ConsensusVerifier for AcceptAllDecider {
    fn verify_bundle(&self, _b: &crate::decider::DeciderBundle) -> bool {
        true
    }
}

/// ⭐ SATOSHI — A NODE THAT JOINS BY DSYNC INHERITS THE ISSUED SAT TOTAL AND THE PENDULUM SNAPSHOT, through the production
/// serve → adopt path (`build_sync_bundle` → `instant_sync`). Before the bundle carried them, a joiner held 0 issued and no
/// snapshot while every node that watched the chain held the chain's (the sync census listed both as uncovered). CALIBRATION:
/// the server issued SAT and holds a non-default snapshot; the fresh joiner starts on neither.
#[test]
fn a_dsync_joiner_inherits_the_issued_sat_total_and_the_pendulum_snapshot() {
    let mut a = crate::node::tests::testnet_party_folding_at_tip();
    for (i, seed) in [&b"sat-join-1"[..], &b"sat-join-2"[..]].iter().enumerate() {
        a.produce(5_000 + 500 * i as u64, Hash32::hash(seed), Hash32::hash(b"mc")).expect("A lays a rewarded block");
        let _ = a.fold_canonical_records();
    }
    let (issued, _) = a.peg().sat_census();
    assert!(issued > 0, "CALIBRATION: A's fold credited its rewards");
    assert!(a.peg_mut_for_test().snapshot_pendulum(6, u128::from(issued)), "A snapshots epoch 6 with every issued SAT bonded");
    // ⛔ the bundle A SERVES (census S-DRAFT-ADOPT): a frozen bundle states the chain at its freeze, so what the joiner must
    // inherit is read from the served bundle itself, never from A's state before the serve
    let bundle = a.served_bundle_for_test();
    let served = (bundle.nullifier.peg_sat_issued, bundle.nullifier.peg_pendulum);
    assert!(served.0 > 0, "CALIBRATION: the served state counts issued SAT");
    assert_ne!(served.1, (0, 10_000), "CALIBRATION: the served state holds a non-default snapshot (more than a third bonded ⇒ share < 100%)");
    let mut b = crate::node::tests::testnet_party_folding_at_tip();
    assert_eq!(b.peg().sat_census(), (0, (0, 10_000)), "CALIBRATION: the fresh joiner holds neither");
    b.set_decider_verifier(Box::new(AcceptAllDecider));
    match b.instant_sync(bundle) {
        crate::sync::AdoptOutcome::Adopted(_) => {}
        other => panic!("B must adopt A's served bundle, got {other:?}"),
    }
    assert_eq!(b.peg().sat_census(), served, "⛔ the joiner did not inherit the chain's issued SAT total and pendulum snapshot");
}

/// INSTRUMENT (2026-10-05, the eclipse netsim's arrival drift; DB-393 B4): what ONE block's SAT reward adds to the block's
/// bytes and what building it costs on the producer's critical path. Prints the measurement; asserts only that the
/// measurement is real (the reward builds, its opening recomputes its note, its sizes are non-zero) — never a budget. Since
/// B4 there is no carrier in any tier: the object is the note, its 32-byte public opening and its clue.
#[test]
fn the_reward_objects_bytes_and_build_time_are_measured() {
    let (rc, _dk) = RewardRecipient::for_test(&[7u8; 32]);
    let t = std::time::Instant::now();
    let r = SatoshiRewardTx::build(&rc, 0, 1_000, None).expect("a reward builds");
    let build_ms = t.elapsed().as_millis();
    let obj = r.to_object();
    let carriage = crate::chain_object::carriage_of(&obj).expect("a reward has a carriage form");
    assert!(r.credit_is_authorised() && !r.note.is_empty(), "CALIBRATION: a real reward whose opening opens its note");
    eprintln!(
        "[sat-reward-bytes] note {} B · opening {} B · object {} B · carriage {} B · build {} ms (DB-393 B4: no carrier)",
        r.note.len(),
        r.opening.len(),
        obj.len(),
        carriage.len(),
        build_ms
    );
}

/// ⭐ DB-393 B4 — THE DEFERRED TEMPLATE LAYS THE REWARD WHOLE. The live runtime's template (`begin_produce`) lays the reward
/// object FIRST in the credit set, its note in `output_notes` and its nullifier in the tag set — nothing is left for
/// `complete_produce_job` to prove (fix A's off-lock prove is deleted with the carrier). The producer completes the job,
/// grinds and grafts, and a PEER fed only that block credits exactly the reward. The inline path (`produce`) is the
/// calibration every other satoshi pin runs.
#[test]
fn db393_b4_the_deferred_template_lays_the_reward_whole_and_a_peer_credits_it() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let first = node_a.produce(5_000, Hash32::hash(b"db393-1"), Hash32::hash(b"mc")).expect("A lays a first block");
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(first, 5_500), RelayOutcome::Added(_)), "the peer grafts the first block");
    let _ = node_b.fold_canonical_records();
    let issued_b = node_b.peg().sat_issued();
    let t = std::time::Instant::now();
    let (block, cover_ids, tx_ids, notes, transition) =
        node_a.produce_template_deferred(6_000, Hash32::hash(b"db393-2"), Hash32::hash(b"mc")).expect("A cuts a template");
    let template_ms = t.elapsed().as_millis();
    let rs = rewards_in(&block);
    assert_eq!(rs.len(), 1, "the deferred template lays exactly one reward object, whole");
    assert!(rs[0].credit_is_authorised(), "its public opening recomputes its note's commitment");
    let cm = rs[0].note_cm().expect("a full-width note");
    assert!(
        block.output_notes.chunks(crate::cover::PQ_NOTE_BYTES).any(|n| n.len() >= 32 && n[..32] == cm),
        "the reward's note rides the template's output_notes"
    );
    // §POLES (ce41a23, 2026-10-25) pads the credit set to its constant shape AFTER the root is stamped; the door binds the
    // root to the REAL prefix (`consensus::bound_padded`), so this pin reads the same prefix (RE-FIXTURED 2026-10-27, lane funds:
    // the assertion hashed the padded bytes and read red since the padding landed — a stale assertion, not a defect).
    // §22 (2026-10-28): the credit set is SEALED under the block's cover key and the root binds the sealed bytes WHOLE —
    // the reward's opening is inside them, readable by a holder of the key and bound into the block id.
    assert_eq!(
        block.header.credit_set_root,
        crate::block::credit_set_root_of(&block.credit_set),
        "the credit-set root binds the reward (and its opening) into the block id"
    );
    assert!(!rewards_in(&block).is_empty(), "the holder reads the reward object out of the sealed set");
    // The job exactly as `NodeRuntime::begin_produce` builds it: the cover and bond inputs resolved under the same lock.
    let pending_cover = node_a.pending_cover_for(&tx_ids);
    let pending_bond = node_a.pending_bond_for(&tx_ids);
    let job = crate::node_runtime::ProduceJob {
        tmpl_output_notes: notes,
        block,
        cover_ids,
        tmpl_tx_ids: tx_ids,
        now_ms: 6_000,
        pending_transition: transition,
        pending_cover,
        pending_bond,
        pending_tree: None,
        template_double: node_a.template_double(),
        ledger_double: node_a.ledger_double(),
        da_cover_key: node_a.da_secret_value(),
    };
    let job = match crate::node_runtime::complete_produce_job(job) {
        Ok(j) => j,
        Err(_) => panic!("the off-lock half completes a reward-carrying template"),
    };
    eprintln!("[db393-b4] template under the lock {template_ms} ms (the reward built inside it, nothing proved)");
    let amount = rs[0].amount;
    let miner = crate::pow::PowMiner::new().expect("the PoUW epoch hasher builds");
    let mut mined = job.block.clone();
    mined.pow_proof = miner.mine(&mut mined.header).expect("A grinds its block");
    let block = node_a
        .graft_mined_own(mined, job.cover_ids, job.tmpl_tx_ids, job.tmpl_output_notes, 6_000)
        .expect("A grafts its own block");
    let _ = node_a.fold_canonical_records();
    let outcome = node_b.ingest_block(block, 6_500);
    assert!(matches!(outcome, RelayOutcome::Added(_)), "the peer grafts it — it answered {outcome:?}");
    let _ = node_b.fold_canonical_records();
    assert_eq!(node_b.peg().sat_issued() - issued_b, amount, "⛔ the PEER did not credit exactly the reward");
}

/// ⛔⛔ DB-393 B4 C2 — A RELAY THAT SWAPS A REWARD'S OPENING BREAKS THE BLOCK. The opening rides the credit set, whose root the
/// header binds, so a relay that points the reward at another owner tag hands the peer a body its own header does not commit —
/// refused at the body door. CALIBRATION: the unmodified block grafts on the same peer.
#[test]
fn db393_b4_a_relay_that_swaps_a_rewards_opening_breaks_the_block_on_the_peer() {
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let blk = node_a.produce(5_000, Hash32::hash(b"db393-swap"), Hash32::hash(b"mc")).expect("A lays a block");
    let mut swapped = blk.clone();
    let mut entries = crate::block::credit_set_iter(&swapped.credit_set, crate::block::credit_seal_key(&swapped.header, swapped.cover_key.as_ref()).as_ref(), &swapped.wide_objects).expect("the set parses");
    let at = entries
        .iter()
        .position(|e| matches!(crate::chain_object::unframe(e), Some((crate::chain_object::Class::SatoshiReward, _))))
        .expect("the block carries its reward");
    let (_, payload) = crate::chain_object::unframe(&entries[at]).expect("framed");
    let mut r = SatoshiRewardTx::decode(payload).expect("the carried reward decodes");
    r.opening = crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&[0x5A1F, 2, 3, 4]));
    entries[at] = crate::chain_object::frame(crate::chain_object::Class::SatoshiReward, &r.encode());
    (swapped.credit_set, swapped.wide_objects) = crate::node::tests::sealed_credit_parts(&swapped, &entries); // §22: sealed, so only the ROOT refuses it
    assert_ne!(swapped.credit_set, blk.credit_set, "PRECONDITION: the relay's body differs");
    assert_eq!(swapped.id(), blk.id(), "the header — and so the id — is the producer's");
    let outcome = node_b.ingest_block(swapped, 5_500);
    assert!(
        !matches!(outcome, RelayOutcome::Added(_)),
        "⛔⛔ DB-393 B4 C2: the peer grafted a block whose reward opening a relay swapped — {outcome:?}"
    );
    let outcome = node_b.ingest_block(blk, 5_600);
    assert!(matches!(outcome, RelayOutcome::Added(_)), "CALIBRATION: the producer's own block grafts — {outcome:?}");
}

/// ⭐⭐⭐ THE BOUND ASSET MINT KEEPS WHAT A NODE TEST OBSERVES AND NEVER PASSES THE REAL DOOR — the testing format's bound-double
/// law (2026-10-02) applied to the asset-mint carrier (DB-393 measured it at 1,828 ms and 100,631 B; since B4 the reward no
/// longer carries one, and the asset mints that still do are what the double serves). In the BOUND tier (the node tests' default): the honest carrier verifies; a moved amount, another
/// asset, another commitment or a flipped byte is REFUSED; and the REAL WHIR verifier refuses the bound carrier. In the PROVEN
/// tier (`MONEROUSD_TEST_CERTS=proven`) the reward carries a real carrier the real door accepts.
#[test]
fn the_bound_asset_mint_binds_amount_asset_and_cm_and_never_passes_the_real_door() {
    use usdm_decider::whir_rec_block as w;
    let sat = crate::satoshi::asset_tag();
    let amount = crate::satoshi::INITIAL_REWARD;
    let opening = usdm_decider::poseidon2_compress::lanes_of(&[0xB0, 1, 2, 3]);
    let t0 = std::time::Instant::now();
    let (carrier, cm) = w::prove_asset_mint_validity_bytes(amount, sat, &opening).expect("an asset mint proves");
    let ms = t0.elapsed().as_millis();
    assert!(w::verify_asset_mint_validity_bytes(&carrier, cm, amount, sat), "CALIBRATION: the honest carrier verifies in this tier");
    if w::asset_mint_carriers_are_bound() {
        assert!(!w::verify_asset_mint_validity_bytes(&carrier, cm, amount + 1, sat), "⛔ a moved amount passed");
        assert!(!w::verify_asset_mint_validity_bytes(&carrier, cm, amount, w::USDM_ASSET_TAG), "⛔ another asset passed");
        let mut other = cm;
        other[0] ^= 1;
        assert!(!w::verify_asset_mint_validity_bytes(&carrier, other, amount, sat), "⛔ another commitment passed");
        let mut flipped = carrier.clone();
        let n = flipped.len();
        flipped[n - 1] ^= 1;
        assert!(!w::verify_asset_mint_validity_bytes(&flipped, cm, amount, sat), "⛔ a flipped byte passed");
        assert!(
            !w::real_asset_mint_door_accepts_for_test(&carrier, cm, amount, sat),
            "⛔⛔ a BOUND carrier passed the REAL asset-mint door"
        );
        eprintln!("[bound-asset-mint] an asset mint proved in {ms} ms (bound tier)");
    } else {
        assert!(w::real_asset_mint_door_accepts_for_test(&carrier, cm, amount, sat), "the proven tier's carrier is real");
        eprintln!("[bound-asset-mint] an asset mint proved in {ms} ms (proven tier)");
    }
}

/// ⛔⛔ DB-393 B4 C4 — A REWARD'S OWNER TAG IS PUBLIC ONCE, AT ITS MINT, AND NEVER AGAIN. B4 publishes `o` so every node can
/// recompute the reward's commitment; that is private only while `o` names nothing (`s` hides `spk`) and no later door
/// re-publishes it beside the note's spend. The mint block, the reward's TRANSFER (the asset-spend door) and its BOND (the SAT
/// bond door) — each transaction and each block that carries it — are searched for the recipient's `ask`, `nk`, seed, `o` and
/// `spk` (`db395_pins::leak_of`). CALIBRATION on REAL bytes: the census FINDS `o` in the mint block (B4's design), so a clean
/// spend or bond is a census that could have fired; and both settle on the peer.
#[test]
fn db393_b4_c4_a_rewards_owner_tag_is_public_once_at_its_mint_and_never_again_by_its_spend_or_its_bond() {
    use crate::db395_pins::{calibrate_c4_detector, leak_of};
    use usdm_decider::whir_rec_block::{asset_note_cm, prove_asset_spend_validity_carrier_bytes, AssetSpendValidityWitness};
    let mut node_a = crate::node::tests::testnet_party_folding_at_tip();
    let mut node_b = crate::node::tests::testnet_party_folding_at_tip();
    let (own, dk) = wallet_of(&node_a);
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    // THE MINT, kept as the peer receives it.
    let mint = node_a.produce(5_000, Hash32::hash(b"b4-c4-mint"), Hash32::hash(b"mc")).expect("node_a lays a block");
    let mint_bytes = postcard::to_allocvec(&mint).expect("a block encodes");
    // §22: the reward object (its public owner tag included) rides the SEALED credit set — a holder of the block's
    // cover key reads it; the wire shows cover. B4's design ("public once, at its mint") is measured on the opened set.
    let mint_opened: Vec<u8> = crate::block::credit_set_iter(&mint.credit_set, crate::block::credit_seal_key(&mint.header, mint.cover_key.as_ref()).as_ref(), &mint.wide_objects)
        .expect("the producer opens its own sealed set")
        .concat();
    let reward = reward_note_bytes(&mint, &rewards_in(&mint)[0].note_cm().expect("cm"));
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(mint, 5_500), RelayOutcome::Added(_)), "the peer grafts the mint");
    let _ = node_b.fold_canonical_records();
    let (value_in, in_owner, tag) = dk.open_asset(&reward).expect("the operator's wallet opens its reward");
    let o = in_owner.opening();
    let hidden = [("ask", in_owner.ask), ("nk", in_owner.nk), ("seed", in_owner.seed), ("spk", in_owner.spk())];
    calibrate_c4_detector(&hidden);
    calibrate_c4_detector(&[("o", o)]);
    assert!(leak_of(&mint_opened, &o).is_some(), "CALIBRATION: the mint block publishes the reward's owner tag to a holder of its cover key (B4's design, §22)");
    assert!(leak_of(&mint_bytes, &o).is_none(), "§22: the block's WIRE shows no owner tag — the credit set is sealed");
    for (name, d) in &hidden {
        assert!(leak_of(&mint_bytes, d).is_none(), "⛔⛔ B4 C4: the reward's mint publishes its recipient's {name}");
    }
    // THE TRANSFER of that reward (the asset-spend door), built as the wallet builds it.
    let (recipient, _) = RewardRecipient::for_test(&[0x5f; 32]);
    let amount = value_in / 3;
    let (to_note, to_opening) = crate::faucet::seal_asset_note(&recipient.scan_ek, &recipient.spk, amount, tag, Some([3u8; 32])).expect("seal to the recipient");
    let (ch_note, ch_opening) = crate::faucet::seal_asset_note(&own.scan_ek, &own.spk, value_in - amount, tag, Some([4u8; 32])).expect("seal change");
    let lc_blind = usdm_decider::whir_rec_block::fresh_lc_blind().expect("the OS CSPRNG draws a membership blinding");
    let w = AssetSpendValidityWitness {
        value_in,
        owner: in_owner,
        value_out: value_in,
        fee: 0,
        lc_blind,
        out0_value: amount,
        out0_opening: to_opening,
        out1_value: value_in - amount,
        out1_opening: ch_opening,
        asset: tag,
    };
    let (carrier, _cms, nf, lc) = prove_asset_spend_validity_carrier_bytes(&w).expect("the transfer proves");
    let reward_leaf = asset_note_cm(value_in, tag, o);
    let (membership_carrier, tip_prev, tip_root, tip_acc, named_record) =
        node_a.own_note_membership_one_step(&b32(reward_leaf), reward_leaf, nf, lc_blind).expect("membership of the reward");
    let t = crate::asset_tx::AssetSpendTx {
        notes: [to_note.to_vec(), ch_note.to_vec()],
        nullifier: b32(nf),
        leaf_commit: lc,
        validity_carrier: carrier,
        membership_carrier,
        member_tuple: Vec::new(),
        named_record,
        tip_prev,
        tip_root,
        tip_acc,
        owner_clues: vec![crate::satoshi::reward_clue(&[0x78; 32], 0), crate::satoshi::reward_clue(&[0x78; 32], 1)],
        slot_tag: None,
    };
    let spend_bytes = t.encode();
    assert_eq!(node_a.execute_asset_spend(&t), crate::node::AssetSpendOutcome::Published, "the transfer pools");
    let spend_blk = node_a.produce(7_000, Hash32::hash(b"b4-c4-spend"), Hash32::hash(b"mc")).expect("the transfer block");
    let spend_blk_bytes = postcard::to_allocvec(&spend_blk).expect("a block encodes");
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(spend_blk, 7_500), RelayOutcome::Added(_)), "the peer grafts the transfer block");
    let _ = node_b.fold_canonical_records();
    assert!(node_b.fold_point_spent_set().holds(&b32(nf)), "CALIBRATION: the census reads a transfer the peer settled");
    // THE BOND of a second reward (the SAT bond door).
    let reward2 = mine_and_share(&mut node_a, &mut node_b, 9_000, b"b4-c4-mint-2");
    let (_, owner2, _) = dk.open_asset(&reward2).expect("the operator's wallet opens its second reward");
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let bond = node_a.build_sat_bond_from_reward(&reward2, &dk, &pk, &sk).expect("the operator's wallet bonds its reward");
    let bond_bytes = bond.to_object();
    assert!(node_a.publish_sat_bond(&bond).is_ok(), "the producer pools the bond");
    let bond_blk = node_a.produce(11_000, Hash32::hash(b"b4-c4-bond"), Hash32::hash(b"mc")).expect("the bond block");
    let bond_blk_bytes = postcard::to_allocvec(&bond_blk).expect("a block encodes");
    let _ = node_a.fold_canonical_records();
    assert!(matches!(node_b.ingest_block(bond_blk, 11_500), RelayOutcome::Added(_)), "the peer grafts the bond block");
    let _ = node_b.fold_canonical_records();
    assert_eq!(node_b.validators().bond_of(&vid), u128::from(bond.weight), "CALIBRATION: the census reads a bond the peer seated");
    eprintln!(
        "[b4-c4] searched: mint block {} B, transfer {} B + block {} B, bond {} B + block {} B",
        mint_bytes.len(),
        spend_bytes.len(),
        spend_blk_bytes.len(),
        bond_bytes.len(),
        bond_blk_bytes.len()
    );
    let first = [("ask", in_owner.ask), ("nk", in_owner.nk), ("seed", in_owner.seed), ("o", o), ("spk", in_owner.spk())];
    let second = [("ask", owner2.ask), ("nk", owner2.nk), ("seed", owner2.seed), ("o", owner2.opening()), ("spk", owner2.spk())];
    for (what, bytes, secrets) in [
        ("the reward's transfer", &spend_bytes, &first),
        ("the block carrying the transfer", &spend_blk_bytes, &first),
        ("the second reward's bond", &bond_bytes, &second),
        ("the block carrying the bond", &bond_blk_bytes, &second),
    ] {
        for (name, d) in secrets.iter() {
            if let Some(enc) = leak_of(bytes, d) {
                panic!("⛔⛔ B4 C4: {what} publishes the input owner's {name} ({enc} form) — the owner tag must be public once, at the mint");
            }
        }
    }
}

/// ⭐⭐⭐ §BR-13 item 4 — THE SAT-SUPPLY CENSUS: SAT has exactly three doors (the block reward, the genesis set, a spend that
/// conserves SAT), so every chain class names, in `Class::sat_door` (an exhaustive match: a class without its row does not
/// compile), HOW a SAT note cannot enter through it; this census checks every row has an allowed form and exactly two rows
/// are minting doors (a fourth door is never silent). TAMPERS, live: a bridge credit naming the
/// SAT tag is refused by its decode and by the admission door at every allowance (the SAT asset mint's refusal is pinned at
/// `chain_object`'s AssetMint arm). CALIBRATION: the same credit with the USDm tag is admitted under the open-mint allowance.
#[test]
fn sat_has_exactly_three_doors_and_a_credit_or_mint_naming_sat_is_refused_everywhere() {
    use crate::chain_object::{admissible, Class};
    // Every class's door is a compile-time row (`Class::sat_door`): the census here is that each row has one of the forms
    // the three-door law allows — a door, a conserving spend, a refusal, a USDm/wrapped-only note, or no note at all.
    let forms = ["DOOR 1", "DOOR 2", "conserving", "REFUSED", "USDm only", "wrapped assets only", "no note", "no new value", "returns the note"];
    let doors: Vec<(String, &'static str)> = Class::all().into_iter().map(|c| (format!("{c:?}"), c.sat_door())).collect();
    let malformed: Vec<&(String, &'static str)> = doors.iter().filter(|(_, d)| !forms.iter().any(|f| d.starts_with(f))).collect();
    assert!(malformed.is_empty(), "⛔ §BR-13: these classes name a door of no allowed form (a possible fourth door): {malformed:?}");
    assert_eq!(doors.iter().filter(|(_, d)| d.starts_with("DOOR")).count(), 2, "⛔ §BR-13: SAT has exactly two minting doors and one conserving kind");

    let credit = |tag: [u64; 3]| crate::bridge_credit_tx::BridgeCreditTx {
        deposit_id: [0x13; 32],
        asset_tag: tag,
        amount: 1_000,
        note: vec![0x5a; crate::cover::PQ_NOTE_BYTES],
        owner_clue: Vec::new(),
        attestors: Vec::new(),
    };
    let usdm = credit(usdm_decider::whir_rec_block::USDM_ASSET_TAG);
    assert!(
        admissible(&usdm.wire(), 10, crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false),
        "CALIBRATION: a USDm credit under the open-mint allowance is admitted"
    );
    let sat = credit(crate::satoshi::asset_tag());
    let payload = crate::chain_object::unframe(&sat.wire()).map(|(_, p)| p.to_vec()).expect("framed");
    assert!(crate::bridge_credit_tx::BridgeCreditTx::decode(&payload).is_none(), "⛔ §BR-13: a SAT-tagged credit decodes");
    for (allowance, attested) in [(crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false), (u64::MAX, true)] {
        assert!(
            !admissible(&sat.wire(), 10, allowance, attested),
            "⛔⛔ §BR-13: a bridge credit minting SAT was admitted (allowance {allowance}, attested {attested}) — a fourth SAT door"
        );
    }
}
