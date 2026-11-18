// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `bridge_credit_tx::tests` — the tests of `bridge_credit_tx` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `bridge_credit_tx` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`bridge_credit_tx::tests::…`), and `use super::*` reaches `bridge_credit_tx`'s items through the node's re-export.

// the imports of `bridge_credit_tx` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use serde::Deserialize;
#[allow(unused_imports)]
use serde::Serialize;

/// A real node whose genesis identity is exactly `commit` — the red-team split rig: same code,
/// different network identity, nothing else varies.
fn party_with_genesis(commit: Vec<u8>) -> Node {
    let mut p = ChainParams::default();
    p.net_prefix_len = commit.len();
    p.genesis_parity_commit = commit;
    let g = Block {
        cover_key: None,
        wide_objects: Vec::new(),
        tx_bodies: Vec::new(),
        agg_tables: Vec::new(),
        note_commitments: Vec::new(),
        header: crate::block::genesis_header_for_network(&p.genesis_parity_commit),
        tx_ids: vec![],
        pow_proof: Vec::new(),
        output_notes: Vec::new(),
        oli_tags: Vec::new(),
        account_targets: Vec::new(),
        bond_set: Vec::new(),
        // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
        credit_set: Vec::new(),
        dir_set: Vec::new(),
        letter_set: Vec::new(),
        tag_evidence: Vec::new(),
        note_transition: None,
        nullifier_proof: crate::block::NfBlockProof::default(),
        cover_transition: None,
        member_transition: None,
    };
    Node::with_params(g, p).expect("a party with this genesis builds")
}
fn party() -> Node {
    let mut p = ChainParams::default();
    p.genesis_parity_commit = network_genesis_prefix("testnet");
    p.net_prefix_len = p.genesis_parity_commit.len();
    let g = Block {
        cover_key: None,
        wide_objects: Vec::new(),
        tx_bodies: Vec::new(),
        agg_tables: Vec::new(),
        note_commitments: Vec::new(),
        header: crate::block::genesis_header_for_network(&p.genesis_parity_commit),
        tx_ids: vec![],
        pow_proof: Vec::new(),
        output_notes: Vec::new(),
        oli_tags: Vec::new(),
        account_targets: Vec::new(),
        bond_set: Vec::new(),
        // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
        credit_set: Vec::new(),
        dir_set: Vec::new(),
        letter_set: Vec::new(),
        tag_evidence: Vec::new(),
        note_transition: None,
        nullifier_proof: crate::block::NfBlockProof::default(),
        cover_transition: None,
        member_transition: None,
    };
    Node::with_params(g, p).expect("a testnet party builds")
}
use super::{BridgeCreditTx, CreditApply};
use crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit;use crate::block::Block;
use crate::hash::Hash32;
use crate::node::Node;
use crate::params::{network_genesis_prefix, ChainParams};

/// ⭐⭐⭐ THE MINT AUTHORITY, BOTH DIRECTIONS — a credit above the open-mint allowance is REFUSED
/// without a ≥2/3 bonded quorum and ADMITTED with one.
///
/// ⛔⛔⛔ THIS IS THE `Authority::Missing` ENTRY IN `harness::value_creation`, CLOSED. Before it,
/// `chain_object::admissible` decoded a credit, compared its amount to `genesis_mint_allowance` and
/// returned true — nothing asked WHO. On a value-bearing network the allowance is 0, so the class was
/// unsatisfiable: safe by accident, and the bridge could not credit a real deposit either.
///
/// ⭐ THE CALIBRATION IS THE FIRST ARM, NOT AN AFTERTHOUGHT. An "it refuses" test proves nothing
/// unless the same construction is shown to be ADMITTED when it should be — otherwise a credit
/// refused for some unrelated reason reads as authority working
/// ([[reference_refutation_before_green]]).
#[test]
fn a_credit_above_the_allowance_needs_a_bonded_quorum_and_a_forged_one_is_refused() {
    use crate::node::Node;
    use crate::node::tests::genesis_block;

    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let mut node = Node::new(genesis_block()).expect("node boots");
    node.admit_validator(crate::pqauth::pubkey_id(&pk), 20_000, 0)
        .expect("the validator bonds");

    // An amount that CANNOT ride the open-mint allowance — this is the mainnet shape.
    let allowance = node.params().genesis_mint_allowance();
    let amount = allowance.saturating_add(1_000_000).max(1_000_000);
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(Hash32::hash(b"bonded-credit-note").as_bytes());
    let base = BridgeCreditTx {
        deposit_id: *Hash32::hash(b"bonded-credit-deposit").as_bytes(),
        asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
        amount,
        note,
        owner_clue: Vec::new(),
        attestors: Vec::new(),
    };
    let cm = base.note_cm().expect("the note carries a commitment");
    let msg = crate::peg::PegLedger::bridge_credit_msg(
        &base.deposit_id,
        &base.asset_tag,
        base.amount,
        &cm,
        &base.owner_clue,
    );

    // ── ARM 1: NO ATTESTATION ⇒ REFUSED. The pre-fix behaviour would have ADMITTED this.
    assert_eq!(
        crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit(&mut node, &base.wire()),
        CreditApply::NotCredit,
        "⛔⛔⛔ AN UNATTESTED CREDIT ABOVE THE OPEN-MINT ALLOWANCE WAS ADMITTED — that is an \
         infinite mint: anyone who can frame a BridgeCredit object can create value from nothing."
    );

    // ── ARM 2 (THE CALIBRATION): the SAME credit, attested by the bonded validator ⇒ ADMITTED.
    let mut good = base.clone();
    good.attestors = vec![(
        pk.clone(),
        crate::pqauth::ml_dsa_sign(&msg, &sk).expect("the bonded validator signs"),
    )];
    assert_ne!(
        crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit(&mut node, &good.wire()),
        CreditApply::NotCredit,
        "⛔ THE HONEST ATTESTED CREDIT IS REFUSED, so arm 1 proves nothing — a door that refuses \
         everything is not an authority, it is an outage."
    );

    // ── ARM 3: A SIGNATURE OVER A DIFFERENT MESSAGE ⇒ REFUSED. This is what stops an attestation
    // for one deposit being replayed onto another amount or another note.
    let mut forged = base.clone();
    forged.deposit_id = *Hash32::hash(b"a-different-deposit").as_bytes();
    forged.attestors = vec![(
        pk.clone(),
        crate::pqauth::ml_dsa_sign(&msg, &sk).expect("sign the ORIGINAL message"),
    )];
    assert_eq!(
        crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit(&mut node, &forged.wire()),
        CreditApply::NotCredit,
        "⛔⛔⛔ AN ATTESTATION WAS REPLAYED ONTO A DIFFERENT DEPOSIT. The message is \
         domain-separated and binds deposit id, asset, amount AND note commitment precisely so one \
         validator signature cannot authorise a credit it never saw."
    );

    // ── ARM 4: AN UNBONDED KEY ⇒ REFUSED, however well it signs.
    let (out_pk, out_sk) = crate::pqauth::ml_dsa_keypair();
    let mut outsider = base.clone();
    outsider.attestors = vec![(
        out_pk,
        crate::pqauth::ml_dsa_sign(&msg, &out_sk).expect("the outsider signs correctly"),
    )];
    assert_eq!(
        crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit(&mut node, &outsider.wire()),
        CreditApply::NotCredit,
        "⛔⛔⛔ A KEY WITH NO BOND AUTHORISED A MINT. Weight comes from posted bond; a valid \
         signature from nobody is worth nothing, which is the whole definition of the quorum."
    );
}

fn a_credit(tag: &[u8]) -> BridgeCreditTx {
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(Hash32::hash(tag).as_bytes());
    BridgeCreditTx {
        deposit_id: *Hash32::hash(b"foreign-deposit").as_bytes(),
        asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
        amount: 25_000_000,
        note,
        owner_clue: Vec::new(),
        attestors: Vec::new(),
    }
}

/// The published shape carries the note as an output note and NO nullifier — a credit mints, it burns
/// nothing. A nullifier here would spend something the depositor never spent. v32: the blob is the
/// FRAMED wire form (classifiable at the door), the id is the content id of THOSE bytes, and the
/// stamp is ground to the floor the caller passes (8 = the live `pow_stamp_base_bits`).
#[test]
fn a_published_credit_carries_the_note_and_burns_nothing() {
    let c = a_credit(b"deposit-B");
    let tx = c.as_pq_tx(8);
    assert!(tx.nullifiers.is_empty(), "a credit MINTS; a burn belongs to a peg-out");
    assert_eq!(tx.output_notes, c.note, "the credited note is what the block carries");
    assert_eq!(tx.id, crate::mempool::PqTx::content_id(&c.wire()), "the id is the wire content id");
    assert!(
        tx.stamp_work() >= 8,
        "the stamp must be GROUND to the floor — pow_stamp 0 against required 8 bits is why no \
         credit could ever occupy a pool slot (the plan's measured 8c premise)"
    );
    assert!(tx.account_targets.is_empty(), "no owner named — no target bytes");
    assert!(tx.note_clues.is_empty(), "no owner named — no clue bytes");
    // DB-273 §17: an owner rides as its clue, in the exact wire encoding the staging reader parses, and never as
    // a (bucket, ek) account target.
    let mut owned = c.clone();
    owned.owner_clue = vec![0xAB; 16];
    let tx2 = owned.as_pq_tx(8);
    assert!(tx2.account_targets.is_empty(), "⛔ DB-273 §17: a credit wrote a per-wallet account target");
    assert_eq!(tx2.note_clues.len(), 32 + 2 + 16, "cm‖len‖clue");
    assert_ne!(tx2.id, tx.id, "the owner clue is INSIDE the object, so the frame's id binds it");
}

/// Bytes that are not a credit are left completely alone, so the door runs on every blob with no type
/// tag on the wire — and a BARE (unframed) credit encoding is not a credit either: the frame is the
/// one wire encoding.
#[test]
fn anything_that_is_not_a_credit_is_left_alone() {
    let mut n = party();
    assert_eq!(crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit(&mut n, &[0xFF; 24]), CreditApply::NotCredit);
    assert_eq!(crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit(&mut n, b"not a credit at all"), CreditApply::NotCredit);
    let bare = a_credit(b"deposit-C").encode();
    assert_eq!(
        crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit(&mut n, &bare),
        CreditApply::NotCredit,
        "an unframed blob is not classifiable and must be left to the send gate, never guessed"
    );
}

/// ⭐ ITEM-8 CROSS-NODE PIN — the shape of the plan's ONE proof, in process, both nodes real: a
/// credit ADMITTED on `node_a` (through the real `ingest_tx` door, framed, stamped) rides A's
/// produced block, and `node_b` — which never saw any RPC and never pooled the tx — HOLDS the
/// credited note's record after grafting that block; B's door then answers `AlreadyHeld` for a
/// replay of the same deposit, and a staged duplicate on B dies the moment the published copy is
/// reconciled. Asserting what the PEER holds, never what a call returned. RED before 8(b)/8(c) BY
/// CONSTRUCTION: `ingest_tx` refused the class at the door (`chain_object.rs:130` named it), so no
/// block could ever carry a credit and B could never hold one. The replay/staged halves go RED if
/// `apply_chain_bridge_credit` loses its record check or its `unstage_credit_note` call.
#[test]
fn a_published_credit_lands_on_the_peer_and_a_replay_credits_nothing() {
    let mut node_a = party();
    let mut node_b = party();
    // ITEM-8(b) derivation half: the allowance is a PURE function of the genesis identity, so the
    // two independently constructed testnet nodes AGREE on it (the admission rule reads it — a
    // disagreement is two mint laws on one chain), and a default (mainnet-safe, empty-genesis)
    // params set derives ZERO: no open mint anywhere value could be real.
    assert_eq!(
        node_a.params().genesis_mint_allowance(),
        node_b.params().genesis_mint_allowance(),
        "two nodes of one network must derive the SAME open-mint allowance"
    );
    assert_eq!(
        node_a.params().genesis_mint_allowance(),
        crate::params::TESTNET_OPEN_MINT_ALLOWANCE,
        "a testnet genesis derives the open-faucet allowance"
    );
    assert_eq!(
        crate::params::ChainParams::default().genesis_mint_allowance(),
        0,
        "the value-bearing safe default (mainnet / unknown / empty genesis) derives NO open mint"
    );
    let c = a_credit(b"deposit-XN");
    let cm = c.note_cm().expect("cm");
    let bits = node_a.required_stamp_bits();
    node_a
        .ingest_tx(c.as_pq_tx(bits))
        .expect("the framed, stamped credit is admissible on a testnet chain (8b opens the door)");
    let now = node_a
        .dag()
        .get(&node_a.selected_tip().expect("tip"))
        .expect("hdr")
        .header
        .timestamp
        + node_a.params().target_spacing_ms;
    let blk = node_a
        .produce(now, Hash32::hash(b"xn-carry"), Hash32::hash(b"xn-m"))
        .expect("A produces the block that carries the credit");
    assert!(
        blk.output_notes
            .chunks(crate::cover::PQ_NOTE_BYTES)
            .any(|ch| ch.len() >= 32 && ch[..32] == cm),
        "PRECONDITION: the produced block CARRIES the credited note — the tx path, not a local stage"
    );
    node_b.ingest_block(blk, now + 500);
    assert!(
        node_b.holds_record_with_cm(&cm),
        "node_b must hold the credited note's record from the BLOCK alone — it never saw the RPC \
         and never pooled the tx; this is the availability the publication exists for"
    );
    // REPLAY, judged on the PEER: the same deposit arriving again must credit NOTHING on node_b.
    assert_eq!(
        crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit(&mut node_b, &c.wire()),
        CreditApply::AlreadyHeld,
        "INFLATION: node_b acknowledged the same deposit as new after holding its record — a \
         replayed credit must never read as a fresh one on any node"
    );
    // STAGED-DUPLICATE RECONCILE, on the PEER: a copy staged on node_b dies when the published one
    // is reconciled, so one commitment can never ride two block carriages from node_b either.
    node_b.stage_credit_note(c.note.clone());
    let _ = crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit(&mut node_b, &c.wire());
    assert!(
        !node_b.holds_staged_credit(&cm),
        "the staged duplicate MUST be dropped when the published copy lands — otherwise it rides \
         node_b's next produced block and the commitment is carried twice"
    );
}

/// ⭐ RED-TEAM forged-allowance PIN (2026-09-06) — MULTIPLE CREDITS, EACH within the per-credit
/// allowance, must not SUM a single foreign deposit past what that deposit authorises. The attack:
/// one deposit `D`, replayed as several credits whose amounts each pass `amount <= allowance`, so
/// the per-credit compare waves every copy through and the TOTAL minted for `D` exceeds it.
///
/// The design answer this pin FIXES IN PLACE: the door is idempotent BY NOTE COMMITMENT, not by
/// `deposit_id` (`apply_chain_bridge_credit` keys the replay refusal on `holds_record_with_cm`).
/// So the SAME deposit carried under the SAME note commitment is caught here — `AlreadyHeld`, zero
/// second credit — and THAT is the sum-limiting authority at THIS layer: N copies of one credit
/// mint once, not N times. (Distinct-note replay of one deposit is refused upstream by peg.rs's
/// spent-deposit set before a credit is ever framed; on the only value-bearing posture the door
/// admits nothing at all, allowance 0.) Asserting what the PEER holds, never a return value.
/// MEASURED: node_b, after grafting A's block, credits the deposit ONCE; three further apply calls
/// with the identical wire all answer `AlreadyHeld` and the record set does not grow. RED if the
/// cm-keyed idempotency is lost (each replay would read as fresh and the deposit sums without
/// bound). MUST-STAY-GREEN: one commitment, one credit, however many times it is replayed.
#[test]
fn many_replays_of_one_credit_sum_to_exactly_one_mint_on_the_peer() {
    let mut node_a = party();
    let mut node_b = party();
    let c = a_credit(b"deposit-SUM");
    let cm = c.note_cm().expect("cm");
    assert!(
        c.amount <= node_a.params().genesis_mint_allowance(),
        "PRECONDITION: each copy is individually within the per-credit allowance — the sum is the attack"
    );
    let bits = node_a.required_stamp_bits();
    node_a
        .ingest_tx(c.as_pq_tx(bits))
        .expect("the framed, stamped credit is admissible on a testnet chain");
    let now = node_a
        .dag()
        .get(&node_a.selected_tip().expect("tip"))
        .expect("hdr")
        .header
        .timestamp
        + node_a.params().target_spacing_ms;
    let blk = node_a
        .produce(now, Hash32::hash(b"sum-carry"), Hash32::hash(b"sum-m"))
        .expect("A produces the block that carries the credit");
    node_b.ingest_block(blk, now + 500);
    assert!(
        node_b.holds_record_with_cm(&cm),
        "PRECONDITION: node_b holds the credited note from the block alone"
    );
    // THE ATTACK: replay the SAME credit many times on node_b. Each answer must be AlreadyHeld —
    // the deposit is minted exactly once no matter how many times it is presented.
    for attempt in 0..3 {
        assert_eq!(
            crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit(&mut node_b, &c.wire()),
            CreditApply::AlreadyHeld,
            "INFLATION (replay {attempt}): a re-presented credit must never read as a fresh mint — \
             that is exactly how N in-allowance copies would sum one deposit past its authority"
        );
    }
}

/// ⭐ RED-TEAM forged-allowance PIN (2026-09-06) — BENEFICIARY forgery: a credit that names an
/// owner target must file the note to the commitment the note ACTUALLY carries, so an attacker
/// cannot redirect a legitimate deposit's value to a beneficiary of their choosing by pairing a
/// real note with a mismatched target. Pure structural assertion on the wire the credit builds:
/// the account-target bytes are keyed by the note's OWN cm, never a caller-chosen key.
///
/// ROOT-LAYER: `as_pq_tx` derives the target key from `self.note_cm()` (the note's first 32 bytes),
/// not from any independent field — so the filed bucket is bound to the note that opens the value,
/// and the graft-side filing (`stage_carried_account_targets`) reads that same cm.
/// MEASURED: the target blob's leading 32 bytes EQUAL the note's cm; a credit whose note is swapped
/// changes those 32 bytes with it. RED if a beneficiary key were ever carried independently of the
/// note. MUST-STAY-GREEN: target key == note cm, by construction.
/// ⛔⛔⛔ DB-273 §17 (RED-FIRST MEASUREMENT, 2026-09-29) — A PEER MUST NOT CREDIT A COPY OF AN ATTESTED CREDIT WHOSE
/// OWNER A RELAY STRIPPED. The bonded quorum signs `bridge_credit_msg(deposit ‖ asset ‖ amount ‖ note_cm)`, which does
/// NOT cover the owner, so a relay can re-frame an attested credit with its owner removed: the frame's id moves, every
/// signature still verifies, and the deposit's first-lands-wins dedupe lets the stripped copy settle the note UNFILED
/// for its owner (a seed-restore miss once DB-273 (B) retires the bucket read) — DB-351's class on the object path.
/// RED until §17 binds the owner into the attested message.
/// - A is a producer handed the stripped copy (it skips its own door, as any producer can); B is fed only A's blocks.
/// - CALIBRATION: an owner-named, attested credit of ANOTHER deposit rides A's first block and B credits it, so the
///   pin is not passing because B credits nothing above the allowance.
/// TWO-PARTY-REVIEWED: A (the producer carrying the relay's copy) and B (the peer); the claim is what B HOLDS.
#[test]
fn db273_s17_a_peer_does_not_credit_a_copy_whose_owner_a_relay_stripped() {
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let bonded = || {
        let mut n = party();
        n.admit_validator(crate::pqauth::pubkey_id(&pk), 20_000, 0).expect("the validator bonds");
        n
    };
    let (mut node_a, mut node_b) = (bonded(), bonded());
    let above = node_a.params().genesis_mint_allowance().saturating_add(1_000_000).max(1_000_000);
    let attested = |tag: &[u8]| {
        let mut c = a_credit(tag);
        c.amount = above;
        c.owner_clue = vec![0xC1; 64];
        let cm = c.note_cm().expect("cm");
        let msg = crate::peg::PegLedger::bridge_credit_msg(&c.deposit_id, &c.asset_tag, c.amount, &cm, &c.owner_clue);
        c.attestors = vec![(pk.clone(), crate::pqauth::ml_dsa_sign(&msg, &sk).expect("the custodian signs"))];
        c
    };
    let bits = node_a.required_stamp_bits();
    let lay = |a: &mut Node, b: &mut Node, c: &BridgeCreditTx| {
        a.ingest_tx_unverified(c.as_pq_tx(bits)).expect("A pools the frame");
        let now = a.dag().get(&a.selected_tip().expect("tip")).expect("hdr").header.timestamp
            + a.params().target_spacing_ms;
        let blk = a.produce(now, Hash32::hash(b"s17-f"), Hash32::hash(b"s17-m")).expect("A lays the block");
        b.ingest_block(blk, now + 500);
    };
    // CALIBRATION: an owner-named, attested credit is carried and credited on B.
    let honest = attested(b"deposit-S17-HONEST");
    lay(&mut node_a, &mut node_b, &honest);
    assert!(
        node_b.holds_record_with_cm(&honest.note_cm().expect("cm")),
        "CALIBRATION: B credits an attested, owner-named credit carried in A's block"
    );
    // THE ATTACK: the relay strips the owner of another attested credit and A carries that copy.
    let owned = attested(b"deposit-S17-STRIP");
    let mut stripped = owned.clone();
    stripped.owner_clue = Vec::new();
    assert_ne!(stripped.wire(), owned.wire(), "premise: the stripped frame is a different object");
    lay(&mut node_a, &mut node_b, &stripped);
    assert!(!node_b.holds_record_with_cm(&owned.note_cm().expect("cm")),
        "⛔⛔⛔ DB-273 §17: B credited a copy whose owner a relay stripped — the quorum's signatures do not cover \
         the owner, so the stripped copy settles the deposit UNFILED for its owner"
    );
}

#[test]
fn a_credit_target_is_bound_to_the_notes_own_commitment_not_a_chosen_key() {
    let mut owned = a_credit(b"deposit-BENE");
    owned.owner_clue = vec![0xC1; 64];
    let cm = owned.note_cm().expect("cm");
    let tx = owned.as_pq_tx(8);
    assert!(tx.note_clues.len() >= 32, "an owner-named credit carries its clue");
    assert_eq!(
        &tx.note_clues[..32],
        &cm[..],
        "FORGERY GUARD: the clue's filing key MUST be the note's own commitment — a clue keyed \
         to any other value would file a real deposit's note under an attacker-chosen beneficiary"
    );
    // Changing the note changes the key with it — the binding is to the note, not to a free field.
    let mut other = owned.clone();
    other.note[..32].copy_from_slice(Hash32::hash(b"a-different-note").as_bytes());
    let cm2 = other.note_cm().expect("cm2");
    let tx2 = other.as_pq_tx(8);
    assert_ne!(cm, cm2, "the other note is a different commitment");
    assert_eq!(
        &tx2.note_clues[..32],
        &cm2[..],
        "the clue key tracks the note commitment — it cannot be pinned to a stale beneficiary"
    );
}

/// ⭐ RED-TEAM NETWORK-SPLIT TAMPER PIN (the tx door) — the IDENTICAL credit bytes a testnet node
/// genuinely admits are REFUSED at the door of a mainnet node AND of a node on an attacker-defined
/// genesis (the testnet identity extended by one byte — the sharpest split identity, refused only if
/// the allowance derivation is whole-bytes exact). ROOT-LAYER: `Node::ingest_tx` passes its OWN
/// params-derived allowance into `chain_object::admissible` — this pin proves the wiring end to end on
/// real nodes of three networks, not the pure function with a hand-passed parameter. Judged on what
/// each refusing party HOLDS after the injection (no record of the commitment, and its next produced
/// block carries no such note), never on the call's word alone.
/// RED-run: inverted the mainnet expectation against the live door (asserted the mainnet node ADMITS
/// the testnet credit) and ran this pin — it FAILED with `InvalidProof`, proving the door genuinely
/// refuses and the assertion can fail; restored, GREEN.
/// MEASURED: 0 is the allowance both non-testnet doors derive below, asserted in-line.
/// MUST-STAY-GREEN: a_published_credit_lands_on_the_peer_and_a_replay_credits_nothing,
/// a_mint_class_is_unsatisfiable_where_the_genesis_derives_no_allowance.
#[test]
fn a_testnet_valid_credit_is_refused_at_a_mainnet_and_unknown_genesis_door() {
    let mut node_t = party();
    let mut node_m = party_with_genesis(network_genesis_prefix("mainnet"));
    let mut split_commit = network_genesis_prefix("testnet");
    split_commit.push(0u8);
    let mut node_u = party_with_genesis(split_commit);
    // The doors below judge with THEIR OWN derived parameter — pin what each one derived.
    assert_eq!(node_m.params().genesis_mint_allowance(), 0, "mainnet derives NO open mint");
    assert_eq!(
        node_u.params().genesis_mint_allowance(),
        0,
        "an unknown (testnet-adjacent) genesis derives NO open mint — fail-closed, not fail-testnet"
    );
    let c = a_credit(b"deposit-SPLIT");
    let cm = c.note_cm().expect("cm");
    // PRECONDITION: the very same credit is genuinely admissible where the genesis grants it.
    let bits_t = node_t.required_stamp_bits();
    node_t
        .ingest_tx(c.as_pq_tx(bits_t))
        .expect("PRECONDITION: the credit admits on the testnet door — the forgery below is real");
    // THE FORGERY: inject the same deposit under mainnet parameters. One rule, other parameter: REFUSED.
    let bits_m = node_m.required_stamp_bits();
    assert_eq!(
        node_m.ingest_tx(c.as_pq_tx(bits_m)),
        Err(crate::mempool::MempoolError::InvalidProof),
        "INFLATION: a mainnet door admitted a credit only the TESTNET genesis allows — the \
         allowance must fail-close to 0 on every network whose genesis grants none"
    );
    // And under an attacker-defined genesis that merely CONTAINS the testnet identity: REFUSED.
    let bits_u = node_u.required_stamp_bits();
    assert_eq!(
        node_u.ingest_tx(c.as_pq_tx(bits_u)),
        Err(crate::mempool::MempoolError::InvalidProof),
        "INFLATION: an unknown-network door admitted a testnet credit — a prefix-lenient \
         allowance derivation would open the faucet on an attacker-defined chain"
    );
    // WHAT THE REFUSING PARTIES HOLD — the verdict that counts. Neither holds the commitment's
    // record, and the next block EACH produces carries no note opening to it: the refused credit can
    // never ride out of either party into its network.
    for (name, party) in [("mainnet", &mut node_m), ("unknown-genesis", &mut node_u)] {
        assert!(
            !party.holds_record_with_cm(&cm),
            "the {name} party must hold NO record of the refused credit"
        );
        let now = party
            .dag()
            .get(&party.selected_tip().expect("tip"))
            .expect("hdr")
            .header
            .timestamp
            + party.params().target_spacing_ms;
        let blk = party
            .produce(now, Hash32::hash(b"split-refused"), Hash32::hash(b"split-refused-m"))
            .expect("the refusing party still produces (refusal is per-object, never a halt)");
        assert!(
            !blk.output_notes
                .chunks(crate::cover::PQ_NOTE_BYTES)
                .any(|ch| ch.len() >= 32 && ch[..32] == cm),
            "the {name} party's produced block must NOT carry the refused credit's note"
        );
    }
}

/// ⭐ RED-TEAM NETWORK-SPLIT TAMPER PIN (the block route) — a TESTNET block genuinely carrying an
/// admitted credit, injected into a MAINNET node, applies NOTHING: the mainnet node never grafts it
/// (its parent is the testnet genesis, which a mainnet DAG does not hold) and never records the
/// credited note. ROOT-LAYER: graft-side note recording runs only for a block the DAG ACCEPTED —
/// cross-network isolation rests on the genesis identity being in the ancestry of every block, so the
/// split block can never join. Two real parties; the verdict is what the INJECTED party holds.
/// RED-run: inverted the record expectation (asserted the mainnet node HOLDS the credited note after
/// the injection) and ran this pin — it FAILED, proving the injected block leaves no record and the
/// assertion can fail; restored, GREEN.
/// MEASURED: 0 records of the credited commitment exist on the mainnet node after the injection.
/// MUST-STAY-GREEN: a_published_credit_lands_on_the_peer_and_a_replay_credits_nothing.
#[test]
fn a_testnet_block_carrying_a_credit_never_applies_on_a_mainnet_node() {
    let mut node_t = party();
    let mut node_m = party_with_genesis(network_genesis_prefix("mainnet"));
    let c = a_credit(b"deposit-SPLIT-BLOCK");
    let cm = c.note_cm().expect("cm");
    let bits = node_t.required_stamp_bits();
    node_t
        .ingest_tx(c.as_pq_tx(bits))
        .expect("the credit admits on its OWN network");
    let now = node_t
        .dag()
        .get(&node_t.selected_tip().expect("tip"))
        .expect("hdr")
        .header
        .timestamp
        + node_t.params().target_spacing_ms;
    let blk = node_t
        .produce(now, Hash32::hash(b"split-carry"), Hash32::hash(b"split-m"))
        .expect("the testnet node produces the block that carries the credit");
    assert!(
        blk.output_notes
            .chunks(crate::cover::PQ_NOTE_BYTES)
            .any(|ch| ch.len() >= 32 && ch[..32] == cm),
        "PRECONDITION: the injected block genuinely CARRIES the credited note"
    );
    let out = node_m.ingest_block(blk, now + 500);
    assert!(
        !matches!(out, crate::relay::RelayOutcome::Added(_)),
        "a testnet block must never GRAFT into a mainnet DAG — the genesis split is the isolation"
    );
    assert!(
        !node_m.holds_record_with_cm(&cm),
        "INFLATION: the mainnet node recorded a note carried by a foreign-network block it never \
         grafted — cross-network injection must apply nothing"
    );
}

/// ⭐ RED-TEAM PROBE (the rogue-producer route, same attack surface) — a MAINNET producer whose
/// modified binary skips its own admission door (`node_a`, the rogue) pools the testnet-only credit
/// raw, produces a block, and hands it to an honest MAINNET peer (`node_b`). The honest peer must not
/// end up holding the credited note's record: `chain_object::admissible` runs at the POOL door only,
/// and the block body carries `output_notes` with no allowance re-check at graft — so if the block
/// grafts, the mint lands. This pin asserts the forgery FAILS on the honest peer; if it instead
/// PASSES the graft, that is a confirmed funds-safety hole in the door's placement (door-only,
/// producer-honest) and this pin is its specification. RED/GREEN status is reported by the run
/// itself — see the lane report. Two nodes in the pin; the verdict is what node_b HOLDS.
/// MEASURED: 1 block produced by the rogue carrying the credited commitment when the pool holds it.
/// MUST-STAY-GREEN: a_testnet_valid_credit_is_refused_at_a_mainnet_and_unknown_genesis_door.
/// ROOT-LAYER: the honest peer's graft path is the last door value crosses between networks' rules.
#[test]
fn a_rogue_mainnet_producer_cannot_mint_a_credit_through_the_block_body() {
    let mut node_a = party_with_genesis(network_genesis_prefix("mainnet"));
    let mut node_b = party_with_genesis(network_genesis_prefix("mainnet"));
    let c = a_credit(b"deposit-ROGUE-MINT");
    let cm = c.note_cm().expect("cm");
    let bits = node_a.required_stamp_bits();
    // The adversary's binary has no door: raw pool admission (test-only hook models exactly that).
    node_a
        .ingest_tx_unverified(c.as_pq_tx(bits))
        .expect("the rogue's own pool takes the blob raw — that is the attack model");
    let now = node_a
        .dag()
        .get(&node_a.selected_tip().expect("tip"))
        .expect("hdr")
        .header
        .timestamp
        + node_a.params().target_spacing_ms;
    let blk = node_a
        .produce(now, Hash32::hash(b"rogue-carry"), Hash32::hash(b"rogue-m"))
        .expect("the rogue produces");
    let carried = blk
        .output_notes
        .chunks(crate::cover::PQ_NOTE_BYTES)
        .any(|ch| ch.len() >= 32 && ch[..32] == cm);
    let out = node_b.ingest_block(blk, now + 500);
    assert!(
        !node_b.holds_record_with_cm(&cm),
        "CONFIRMED FUNDS-SAFETY HOLE: an honest mainnet node holds the record of a credit its \
         network's allowance forbids — the rogue block carried it (carried={carried}, \
         outcome={out:?}); the mint-authority rule binds only the POOL door, and a producer that \
         skips its own door mints on every honest peer at graft"
    );
}

/// ⭐⭐⭐ THE MINT AUTHORITY AT THE **GRAFT** DOOR, BOTH DIRECTIONS, ACROSS TWO NODES — the half
/// `a_rogue_mainnet_producer_cannot_mint_a_credit_through_the_block_body` cannot prove.
///
/// ⛔⛔⛔ WHY A REFUSAL PIN ALONE IS NOT ENOUGH, AND WHY THIS ONE IS A FUNDS-LOSS PIN. The rogue pin
/// proves the graft door REFUSES an unauthorised credit. It says nothing about whether the graft door
/// ADMITS an AUTHORISED one — and a door that refuses everything is not an authority, it is an
/// outage. On mainnet the open-mint allowance is 0, so EVERY real bridge credit is "above the
/// allowance" and reaches value only through the bonded quorum. If the pool door admitted an attested
/// credit and the graft door refused it, the producer would hold the depositor's note and every
/// honest peer would hold nothing: the deposit is taken and the money is gone on the network that
/// counts. That asymmetry is invisible to a one-node test and to a refusal-only pin, which is exactly
/// why both arms live here, on two nodes, with the verdict read from what the PEER holds.
///
/// ⛔ THE PEER NEVER SEES THE TRANSACTION. `node_b` never pools the tx and never calls
/// `apply_chain_bridge_credit`; the note reaches it through `Block::output_notes` judged by
/// `graft_admitted_notes` against the block's own §BA `credit_set`. So the verdict this pin reads is
/// the GRAFT door's, on the block body alone — the seam where the hole lived.
///
/// ⭐ THE BONDED SET IS CHAIN-DERIVED, WHICH IS WHY BOTH PARTIES CAN HOLD IT. Each node admits the
/// same validator, modelling both having folded the same `bond_set` from the chain, and the pin
/// ASSERTS the two agree before it trusts either verdict — a divergent bonded set would be two mint
/// laws on one chain and is the failure this assert exists to catch. ⛔ This is NOT the
/// local-decides-truth trap: neither node authors a correction and neither consults local state to
/// override the chain; both evaluate the SAME chain-folded quorum over the SAME carried signatures
/// and reach the same answer, which is what makes the two doors' verdicts identical by construction
/// ([[feedback_local_node_deciding_truth_trap]]).
///
/// MEASURED 2026-09-16, and the calibration NAMED THE DOOR. With the quorum, `node_b` holds the
/// credited record from the block alone; with the SAME credit's attestation stripped and carried by
/// a rogue's block, `node_d` holds nothing. The load-bearing door is the §BA `credit_set` loop in
/// `graft_admitted_notes` — the one a peer WITHOUT the tx body crosses — and forcing its
/// `credit_attested` argument takes this pin RED in both directions: hardcoded `false` ⇒ arm 1 fails
/// with *"FUNDS LOST AT THE GRAFT DOOR"*; hardcoded `true` ⇒ arm 2 fails with *"INFINITE MINT"*.
/// ⛔ THE CALIBRATION ALSO CORRECTED A WRONG GUESS ABOUT WHICH DOOR THIS IS. Forcing the argument at
/// the neighbouring pooled-tx door (`if !admissible(&tx.blob, …)`) changed NOTHING in either
/// direction — that lane only judges a framed object whose transaction this node already HOLDS, and
/// a peer grafting a block it never pooled never reaches it. A door named from reading the code
/// rather than from a measurement is a guess; this one was measured.
/// MUST-STAY-GREEN: a_rogue_mainnet_producer_cannot_mint_a_credit_through_the_block_body,
/// a_credit_above_the_allowance_needs_a_bonded_quorum_and_a_forged_one_is_refused.
/// ⭐⭐⭐ DB-274 P4 (§8.10 H1 / §8.11) — TWO FOLD CURSORS, ONE CREDIT VERDICT. RED FIRST, on two nodes.
///
/// A credit's WEIGHT was judged at GRAFT against each node's own folded bonded set, and nodes stand at different
/// fold cursors. Here V's unbond (block U) is folded on A (fold depth 0) before A grafts the credit block X, while B
/// (fold depth 4) still holds V's weight when it builds and grafts X. B recorded the credit and A refused it: two
/// ledgers for one chain. After P4 the weight is judged once, at X's FOLD, in the canonical pre-state. U precedes X
/// on every node, so every node refuses it.
/// CALIBRATION (arm 2): the same kind of credit carried BEFORE any unbond is recorded by BOTH nodes, so the fold is
/// not a door that refuses every credit.
/// Two parties; the verdict is read from what each PEER holds after both folded past the credit.
#[test]
fn db274_p4_two_fold_cursors_reach_one_credit_verdict() {
    fn pair(depth_a: u64, depth_b: u64) -> (Node, Node) {
        let mut a = party_with_genesis(network_genesis_prefix("mainnet"));
        let mut b = party_with_genesis(network_genesis_prefix("mainnet"));
        for (n, depth) in [(&mut a, depth_a), (&mut b, depth_b)] {
            let mut p = n.params().clone();
            p.governance_set_stake_lock_blocks(0);
            p.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
            p.merge_depth_cap = 4;
            p.record_fold_depth = depth;
            n.set_params(p);
        }
        (a, b)
    }
    fn locked_note(tag: &[u8]) -> Vec<u8> {
        let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        n[..32].copy_from_slice(Hash32::hash(tag).as_bytes());
        n
    }
    fn next_ts(n: &Node) -> u64 {
        n.dag().get(&n.selected_tip().expect("tip")).expect("hdr").header.timestamp + n.params().target_spacing_ms
    }
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let attested_by_v = |tag: &[u8]| {
        let mut c = a_credit(tag);
        let cm = c.note_cm().expect("cm");
        let msg = crate::peg::PegLedger::bridge_credit_msg(&c.deposit_id, &c.asset_tag, c.amount, &cm, &c.owner_clue);
        c.attestors = vec![(pk.clone(), crate::pqauth::ml_dsa_sign(&msg, &sk).expect("V signs"))];
        (c, cm)
    };

    // ── ARM 1: U (V's unbond) then X (a credit only V attests). B lags A by its fold depth.
    let (mut a, mut b) = pair(0, 4);
    assert_eq!(a.params().genesis_mint_allowance(), 0, "PRECONDITION: mainnet — every credit needs the quorum");
    let locked = locked_note(b"p4-locked");
    for n in [&mut a, &mut b] {
        n.admit_bond_unverified(vid, 50_000, locked.clone(), 0);
    }
    let (owner_ek, _dk) = crate::pqkem::keypair();
    let bucket = crate::account_da::bucket_id(b"p4-owner");
    let owner_clue = crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek);
    let (sig, nonce) = a.sign_unbond_for_test(&sk, &vid, &owner_clue);
    assert_eq!(
        a.publish_unbond(&pk, &sig, &owner_clue, nonce),
        crate::node::AssetSpendOutcome::Published,
        "PRECONDITION: V's authenticated unbond enters A's pool"
    );
    let ts_u = next_ts(&a);
    let u = a.produce(ts_u, Hash32::hash(b"p4-u"), Hash32::hash(b"p4-mu")).expect("A produces U");
    let _ = b.ingest_block(u, ts_u + 400);
    assert_eq!(a.validators().bond_of(&vid), 0, "PRECONDITION: U folded on A (depth 0): V holds no weight there");
    assert_eq!(b.validators().bond_of(&vid), 50_000, "PRECONDITION: U has NOT folded on B (depth 4): V still weighs");
    let (credit, cm) = attested_by_v(b"p4-credit-after-unbond");
    let bits = b.required_stamp_bits();
    b.ingest_tx(credit.as_pq_tx(bits))
        .expect("PRECONDITION: B's pool (tip-set ADVICE) still sees V's weight and takes the credit");
    let ts_x = next_ts(&b);
    let x = b.produce(ts_x, Hash32::hash(b"p4-x"), Hash32::hash(b"p4-mx")).expect("B produces X");
    assert!(
        x.output_notes.chunks(crate::cover::PQ_NOTE_BYTES).any(|ch| ch.len() >= 32 && ch[..32] == cm),
        "PRECONDITION: X carries the credit's note, or this arm measures assembly, not the verdict"
    );
    let _ = a.ingest_block(x, ts_x + 400);
    let ts = b.fold_past_for_test(&mut [&mut a], ts_x + 400, b"p4-fold-1");
    let _ = ts;
    let (on_a, on_b) = (a.holds_record_with_cm(&cm), b.holds_record_with_cm(&cm));
    eprintln!("[db274-p4] arm 1 (credit after V's unbond): recorded on A={on_a} B={on_b}");
    assert_eq!(
        on_a, on_b,
        "⛔⛔⛔ DB-274 P4: two honest nodes folded the same chain and hold DIFFERENT records for one credit — the \
         weight was judged against each node's own fold cursor, not the step's canonical pre-state"
    );
    assert!(
        !on_a,
        "⛔ DB-274 P4: V's unbond precedes X in canonical order, so V holds no weight in X's pre-state and the \
         credit it alone attests must be refused on every node"
    );

    // ── ARM 2 (CALIBRATION): the credit rides BEFORE any unbond — V weighs in X's pre-state on every node.
    let (mut a2, mut b2) = pair(0, 4);
    for n in [&mut a2, &mut b2] {
        n.admit_bond_unverified(vid, 50_000, locked.clone(), 0);
    }
    let (credit2, cm2) = attested_by_v(b"p4-credit-before-unbond");
    let bits2 = a2.required_stamp_bits();
    a2.ingest_tx(credit2.as_pq_tx(bits2)).expect("PRECONDITION: the attested credit enters A2's pool");
    let ts2 = next_ts(&a2);
    let x2 = a2.produce(ts2, Hash32::hash(b"p4-x2"), Hash32::hash(b"p4-mx2")).expect("A2 produces X2");
    let _ = b2.ingest_block(x2, ts2 + 400);
    let _ = a2.fold_past_for_test(&mut [&mut b2], ts2 + 400, b"p4-fold-2");
    let (on_a2, on_b2) = (a2.holds_record_with_cm(&cm2), b2.holds_record_with_cm(&cm2));
    eprintln!("[db274-p4] arm 2 (credit before any unbond): recorded on A={on_a2} B={on_b2}");
    assert!(
        on_a2 && on_b2,
        "⛔ CALIBRATION FAILED: an attested credit carried while V weighs must be recorded on BOTH nodes — the fold \
         must not refuse every credit"
    );
}

/// ⛔⛔⛔ DB-274 P4 (§8.12 R / §8.13) — A RESTART MUST NOT TURN A SIDE BLOCK'S CREDIT INTO A PER-NODE VERDICT.
///
/// A restart carries every unfolded SIDE block as a bodiless header shell (`unfolded_carry`, DB-117b), and P4a's
/// fold judges a credit's weight from the block's `credit_set`. The restarted node's shell carries none. Here node B
/// builds side block S with an UNATTESTED credit (its one attestor holds no bond), restarts before S folds, and folds
/// S after node A merges it; A never restarts.
/// EXPECTED RED on P4a as written (A strips the credit at S's fold, the restarted B cannot); GREEN once the shell
/// carries its fold inputs (§8.13). On the pre-P4 code this pin is GREEN, because graft refused the credit on the
/// tip set on both nodes — which is why it is P4a's hole to close before it lands.
/// Two parties; the verdict is read from what each PEER holds, and each asserts it FOLDED S first, so a stuck node
/// cannot pass by folding nothing.
#[test]
fn db274_p4_a_restart_with_an_unfolded_side_block_folds_its_credit_like_the_peer() {
    fn next_ts(n: &Node) -> u64 {
        n.dag().get(&n.selected_tip().expect("tip")).expect("hdr").header.timestamp + n.params().target_spacing_ms
    }
    fn fold_depth_4(n: &mut Node) {
        let mut p = n.params().clone();
        p.record_fold_depth = 4;
        n.set_params(p);
    }
    let mut node_a = party_with_genesis(network_genesis_prefix("mainnet"));
    let mut node_b = party_with_genesis(network_genesis_prefix("mainnet"));
    fold_depth_4(&mut node_a);
    fold_depth_4(&mut node_b);
    // A structurally valid credit that NO bonded quorum attests: its one attestor holds no bond on either node.
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let mut c = a_credit(b"p4-side-credit");
    let cm = c.note_cm().expect("cm");
    let msg = crate::peg::PegLedger::bridge_credit_msg(&c.deposit_id, &c.asset_tag, c.amount, &cm, &c.owner_clue);
    c.attestors = vec![(pk, crate::pqauth::ml_dsa_sign(&msg, &sk).expect("the unbonded key signs"))];

    // 1. B builds side block S carrying it (the rogue staging seam, no pool or assembly door) and withholds it.
    node_b.stage_credit_note(c.note.clone());
    node_b.stage_credit_justifier(c.wire());
    let s = node_b.produce(next_ts(&node_b), Hash32::hash(b"p4-s"), Hash32::hash(b"p4-ms")).expect("B produces S");
    let s_id = s.id();
    assert!(
        s.output_notes.chunks(crate::cover::PQ_NOTE_BYTES).any(|ch| ch.len() >= 32 && ch[..32] == cm),
        "PRECONDITION: S carries the credit's note"
    );
    // 2. A builds the chain X -> X2 without S; B receives both, so S is a SIDE tip on B.
    let ts_x = next_ts(&node_a);
    let x = node_a.produce(ts_x, Hash32::hash(b"p4-sx"), Hash32::hash(b"p4-msx")).expect("A produces X");
    let ts_x2 = next_ts(&node_a);
    let x2 = node_a.produce(ts_x2, Hash32::hash(b"p4-sx2"), Hash32::hash(b"p4-msx2")).expect("A produces X2");
    let _ = node_b.ingest_block(x, ts_x2 + 300);
    let _ = node_b.ingest_block(x2, ts_x2 + 400);
    assert_ne!(node_b.selected_tip(), Some(s_id), "PRECONDITION: S is a SIDE block on B, off the selected tip's past");
    assert!(!node_b.block_record_folded_for_test(&s_id), "PRECONDITION: S has not folded on B before the restart");
    // 3. B restarts: its checkpoint, a fresh node, the restore (the Sim's `restart` shape).
    let row_before = node_b.record_row_for_test(&s_id);
    assert!(row_before.is_some(), "PRECONDITION: B holds S's staged row before the restart");
    // ⭐ §8.14 step 1's con, MEASURED, not declared (lane-recursion 05:08: "state the persisted bytes"): what
    // carrying the one non-idle side block WHOLE costs the checkpoint, against the served bundle's shell carry of
    // the same unfolded list. The same ids ride both; only S's content differs.
    let whole = postcard::to_stdvec(&node_b.checkpoint_carry()).expect("ser").len();
    let shell = postcard::to_stdvec(&node_b.unfolded_carry()).expect("ser").len();
    eprintln!(
        "[db274-p4-restart] checkpoint carry {whole} B vs served-bundle carry {shell} B: one non-idle side block \
         carried whole costs {} B",
        whole.saturating_sub(shell)
    );
    assert!(whole > shell, "⛔ the checkpoint carried S as a shell: its fold inputs did not ride the resume");
    let snap = node_b.export_snapshot().expect("B exports its checkpoint");
    let mut node_b = party_with_genesis(network_genesis_prefix("mainnet"));
    fold_depth_4(&mut node_b);
    assert!(node_b.restore_snapshot(snap), "PRECONDITION: B resumes from its checkpoint");
    // ⛔ §8.14 (lane-recursion's condition): the resume PLACES the carried S, never re-grafts it — S's row on the
    // restarted B is byte-identical to the row it held before the restart (no second graft admission).
    assert_eq!(
        node_b.record_row_for_test(&s_id),
        row_before,
        "⛔ the resume re-grafted S: its staged row changed across B's own restart (a double apply on one node)"
    );
    // 4. A receives S and merges it; B receives the merging block; both fold past it.
    let ts_s = next_ts(&node_a);
    let _ = node_a.ingest_block(s, ts_s);
    let ts_m = next_ts(&node_a);
    let m = node_a.produce(ts_m, Hash32::hash(b"p4-sm"), Hash32::hash(b"p4-msm")).expect("A produces the merge");
    assert!(m.header.parents.contains(&s_id), "PRECONDITION: A's next block merges S");
    let _ = node_b.ingest_block(m, ts_m + 400);
    let _ = node_a.fold_past_for_test(&mut [&mut node_b], ts_m + 400, b"p4-side-fold");
    assert!(node_a.block_record_folded_for_test(&s_id), "PRECONDITION: S FOLDED on A");
    assert!(
        node_b.block_record_folded_for_test(&s_id),
        "PRECONDITION: S FOLDED on the restarted B — a stuck fold would read as 'no record' and pass vacuously"
    );
    let (on_a, on_b) = (node_a.holds_record_with_cm(&cm), node_b.holds_record_with_cm(&cm));
    eprintln!("[db274-p4-restart] unattested side-block credit after B's restart: recorded on A={on_a} B={on_b}");
    assert_eq!(
        on_a, on_b,
        "⛔⛔⛔ DB-274 P4 (§8.12 R): the node that RESTARTED holds a different record for one credit than the node \
         that did not — its checkpoint carried S as a bodiless shell, so its fold could not judge the credit"
    );
    assert!(!on_a, "⛔ the credit's one attestor holds no bond: it must be refused on every node");
}

#[test]
fn an_attested_mainnet_credit_lands_on_the_peer_at_graft_and_an_unattested_one_does_not() {
    let mut node_a = party_with_genesis(network_genesis_prefix("mainnet"));
    let mut node_b = party_with_genesis(network_genesis_prefix("mainnet"));
    assert_eq!(
        node_a.params().genesis_mint_allowance(),
        0,
        "PRECONDITION: mainnet derives NO open mint, so every credit here needs the quorum — if \
         this is ever non-zero the pin stops testing the authority and starts testing the allowance"
    );

    // The chain-folded bonded set, held identically by both parties.
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    node_a.admit_validator(vid, 20_000, 0).expect("the validator bonds on A");
    node_b.admit_validator(vid, 20_000, 0).expect("the validator bonds on B");
    assert_eq!(
        node_a.validators().total_bond(),
        node_b.validators().total_bond(),
        "PRECONDITION: the two parties must hold the SAME bonded weight — a divergent quorum is \
         two mint laws on one chain, and every verdict below would be meaningless"
    );

    let base = a_credit(b"deposit-MAINNET-ATTESTED");
    let cm = base.note_cm().expect("cm");
    assert!(
        base.amount > node_a.params().genesis_mint_allowance(),
        "PRECONDITION: the credit really is above the allowance, or the quorum arm never executes"
    );
    let msg = crate::peg::PegLedger::bridge_credit_msg(
        &base.deposit_id,
        &base.asset_tag,
        base.amount,
        &cm,
        &base.owner_clue,
    );
    let mut attested = base.clone();
    attested.attestors =
        vec![(pk.clone(), crate::pqauth::ml_dsa_sign(&msg, &sk).expect("the bonded validator signs"))];

    // ── ARM 1 (THE CALIBRATION): the attested credit passes A's OWN door, rides a block, and the
    // honest peer records it from the block body.
    let bits = node_a.required_stamp_bits();
    node_a
        .ingest_tx(attested.as_pq_tx(bits))
        .expect("⛔ the attested credit must pass the POOL door — a bridge that cannot credit an \
                 attested mainnet deposit has taken the depositor's money and issued nothing");
    let now = node_a
        .dag()
        .get(&node_a.selected_tip().expect("tip"))
        .expect("hdr")
        .header
        .timestamp
        + node_a.params().target_spacing_ms;
    let blk = node_a
        .produce(now, Hash32::hash(b"attested-carry"), Hash32::hash(b"attested-m"))
        .expect("A produces the block that carries the attested credit");
    assert!(
        blk.output_notes
            .chunks(crate::cover::PQ_NOTE_BYTES)
            .any(|ch| ch.len() >= 32 && ch[..32] == cm),
        "PRECONDITION: assembly let the attested note ride — if the ASSEMBLY door refuses it, arm 1 \
         proves nothing about graft and the mint authority is broken one seam earlier"
    );
    node_b.ingest_block(blk, now + 500);
    assert!(
        node_b.holds_record_with_cm(&cm),
        "⛔⛔⛔ FUNDS LOST AT THE GRAFT DOOR: the pool and assembly doors admitted a credit a \
         bonded ≥2/3 quorum attests, and the honest peer recorded NOTHING. The depositor's money is \
         on the producer alone; every other node on the network holds no note for it."
    );

    // ── ARM 2 (THE REFUTATION), AND IT MUST REACH THE SAME DOOR ARM 1 DID. The SAME credit with the
    // attestation stripped must reach the peer as nothing at all.
    //
    // ⛔ A ROGUE THAT ONLY SKIPS THE POOL DOOR NEVER EXERCISES GRAFT. Pooling the unattested blob
    // raw (`ingest_tx_unverified`) leaves the ASSEMBLY door standing, which refuses it and produces a
    // block carrying nothing — the peer would then hold nothing for a reason that has nothing to do
    // with the graft door, and this arm would silently degrade into a second assembly test while
    // still reading green. So the rogue is modelled at the seam that skips assembly too: the note is
    // STAGED directly onto the block with its object as the §BA justifier, exactly as a modified
    // binary would carry it, and the arm ASSERTS the block really carries the commitment before it
    // reads the peer's verdict. That assertion is what keeps this a graft-door measurement.
    let mut node_c = party_with_genesis(network_genesis_prefix("mainnet"));
    let mut node_d = party_with_genesis(network_genesis_prefix("mainnet"));
    node_c.admit_validator(vid, 20_000, 0).expect("the validator bonds on C");
    node_d.admit_validator(vid, 20_000, 0).expect("the validator bonds on D");
    node_c.stage_credit_note(base.note.clone());
    node_c.stage_credit_justifier(base.wire());
    let now_c = node_c
        .dag()
        .get(&node_c.selected_tip().expect("tip"))
        .expect("hdr")
        .header
        .timestamp
        + node_c.params().target_spacing_ms;
    let blk_c = node_c
        .produce(now_c, Hash32::hash(b"unattested-carry"), Hash32::hash(b"unattested-m"))
        .expect("the rogue produces");
    assert!(
        blk_c
            .output_notes
            .chunks(crate::cover::PQ_NOTE_BYTES)
            .any(|ch| ch.len() >= 32 && ch[..32] == cm),
        "PRECONDITION: the rogue's block must genuinely CARRY the unattested note — if it does not,              this arm is measuring the producer's own door and proves nothing about the peer's graft door"
    );
    node_d.ingest_block(blk_c, now_c + 500);
    assert!(
        !node_d.holds_record_with_cm(&cm),
        "⛔⛔⛔ INFINITE MINT: an honest peer recorded a mainnet credit no bonded quorum attests. \
         The same commitment that arm 1 admits WITH a quorum must be worthless WITHOUT one, or the \
         quorum is decoration and anyone who can frame a BridgeCredit object creates value."
    );
}

/// A credit that cannot be applied is refused at decode rather than half-understood.
#[test]
fn a_zero_amount_or_a_stub_note_is_refused_at_decode() {
    let mut zero = a_credit(b"z");
    zero.amount = 0;
    assert!(BridgeCreditTx::decode(&zero.encode()).is_none(), "a zero credit is not a credit");
    let mut stub = a_credit(b"s");
    stub.note = vec![1u8; 8];
    assert!(BridgeCreditTx::decode(&stub.encode()).is_none(), "a note with no commitment credits nobody");
}

/// Re-house a well-formed credit tx around a FORGED blob, exactly as an attacker would: the content
/// id is recomputed for the new bytes (a wrong id dies at `InvalidId` before the door is even asked,
/// which would let the frame gate hide behind the id gate), the weight matches, and the anti-spam
/// stamp is ground to `need` so the stamp gate cannot be the thing that refuses it either. What is
/// left standing between the forged bytes and the pool is ONLY the class door under attack.
fn retagged(mut tx: crate::mempool::PqTx, blob: Vec<u8>, need: u32) -> crate::mempool::PqTx {
    tx.blob = blob;
    tx.id = crate::mempool::PqTx::content_id(&tx.blob);
    tx.weight = tx.blob.len() as u32;
    let mut s = 0u64;
    loop {
        tx.pow_stamp = s;
        if tx.stamp_work() >= need {
            break;
        }
        s = s.wrapping_add(1);
    }
    tx
}

/// ⭐ RED-TEAM STAMP-AND-FRAME PIN — a credit whose `pow_stamp` grinds BELOW the pool's required
/// stamp bits is refused by BOTH independent nodes' real doors (`ingest_tx`), by name
/// (`InsufficientStampWork`), with NOTHING applied: no pool slot on either node and no note record
/// on either node. This pin goes RED if the stamp gate is ever ordered AFTER any state write, or if
/// a mint class is ever exempted from the stamp floor (free flooding + a free mint carriage).
#[test]
fn an_understamped_credit_is_refused_on_node_a_and_node_b_with_nothing_applied() {
    let mut node_a = party();
    let mut node_b = party();
    let c = a_credit(b"understamped");
    let cm = c.note_cm().expect("cm");
    let need = node_a.required_stamp_bits();
    assert!(need >= 1, "PRECONDITION: the live floor must charge SOME work, or this pin is vacuous");
    let mut tx = c.as_pq_tx(need);
    // Degrade the stamp: find a `pow_stamp` whose work is strictly below the floor (for an 8-bit
    // floor, 255 of 256 values qualify — the first few tries find one deterministically).
    let mut s = 0u64;
    loop {
        tx.pow_stamp = s;
        if tx.stamp_work() < need {
            break;
        }
        s = s.wrapping_add(1);
    }
    assert!(tx.stamp_work() < need, "PRECONDITION: the forgery really is understamped");
    for (name, node) in [("node_a", &mut node_a), ("node_b", &mut node_b)] {
        let verdict = node.ingest_tx(tx.clone());
        assert!(
            matches!(
                verdict,
                Err(crate::mempool::MempoolError::InsufficientStampWork { .. })
            ),
            "{name}: an understamped credit must be refused BY NAME at the stamp gate, got {verdict:?}"
        );
        assert!(
            !node.mempool().contains(&tx.id),
            "{name}: a refused credit must occupy NO pool slot — refusal with residue is partial application"
        );
        assert!(
            !node.holds_record_with_cm(&cm),
            "{name}: a refused credit must credit NOTHING — no record may exist for its commitment"
        );
    }
}

/// ⭐ RED-TEAM STAMP-AND-FRAME PIN — a TRUNCATED frame is refused at BOTH independent nodes' doors,
/// at every cut point: mid-magic and magic-only (not a frame at all — the send gate judges and
/// refuses non-carrier bytes), magic+class with the payload gone, and the payload minus its final
/// byte (postcard's tail is load-bearing; a short read refuses, never guesses). Nothing is applied.
/// This pin goes RED if `unframe` ever pads a short blob or `decode` ever tolerates a short payload.
#[test]
fn a_truncated_credit_frame_is_refused_on_node_a_and_node_b() {
    let mut node_a = party();
    let mut node_b = party();
    let c = a_credit(b"truncated");
    let cm = c.note_cm().expect("cm");
    let wire = c.wire();
    let need = node_a.required_stamp_bits();
    for cut in [2usize, 4, 5, wire.len() - 1] {
        let tx = retagged(c.as_pq_tx(need), wire[..cut].to_vec(), need);
        for (name, node) in [("node_a", &mut node_a), ("node_b", &mut node_b)] {
            let verdict = node.ingest_tx(tx.clone());
            assert!(
                verdict.is_err(),
                "{name}: FORGERY at cut {cut}/{}: a truncated frame must be refused, got {verdict:?}",
                wire.len()
            );
            assert!(!node.mempool().contains(&tx.id), "{name}: no pool slot for a refused truncation");
            assert!(!node.holds_record_with_cm(&cm), "{name}: no record for a refused truncation");
        }
    }
}

/// ⭐ RED-TEAM STAMP-AND-FRAME PIN — an OVERSIZED frame (the valid credit payload with trailing
/// bytes appended) is NOT another admissible encoding of the same deposit. The forgery costs an
/// attacker one byte: the padded blob hashes to a DIFFERENT content id, so the pool's by-id dedup
/// (`AlreadyKnown`) is blind to it — if the door admits it, ONE deposit occupies unboundedly many
/// pool slots and the same mint rides block carriages repeatedly. ONE object, ONE encoding, on BOTH
/// nodes. This pin goes RED while any class's `decode` tolerates trailing bytes.
#[test]
fn an_oversized_credit_frame_is_refused_on_node_a_and_node_b() {
    let mut node_a = party();
    let mut node_b = party();
    let c = a_credit(b"oversized");
    let need = node_a.required_stamp_bits();
    let honest = c.as_pq_tx(need);
    let honest_id = honest.id;
    node_a
        .ingest_tx(honest)
        .expect("PRECONDITION: the honest one-encoding wire admits on node_a");
    let mut padded_wire = c.wire();
    padded_wire.extend_from_slice(b"trailing-forgery");
    let tx = retagged(c.as_pq_tx(need), padded_wire, need);
    assert_ne!(
        tx.id, honest_id,
        "the trailing bytes change the content id — by-id dedup CANNOT be the defence here"
    );
    for (name, node) in [("node_a", &mut node_a), ("node_b", &mut node_b)] {
        let verdict = node.ingest_tx(tx.clone());
        assert!(
            verdict.is_err(),
            "{name}: FORGERY ACCEPTED — a padded re-encoding of an already-pooled deposit was \
             admitted as a fresh object ({verdict:?}); one deposit now rides multiple carriages"
        );
        assert!(!node.mempool().contains(&tx.id), "{name}: no pool slot for a padded re-encoding");
    }
}

/// ⭐ RED-TEAM STAMP-AND-FRAME PIN — wrong MAGIC, an unknown class byte, and a credit BODY wearing
/// the OrderFill CLASS tag are each refused at BOTH independent nodes' doors. The tag decides which
/// law judges the bytes; bytes under the wrong law must die under that law, and bytes under no law
/// fall to the send gate where a non-carrier blob dies. Nothing is applied on either node. This pin
/// goes RED if `unframe` ever guesses a class or the fill arm ever admits an undecodable payload.
#[test]
fn wrong_magic_unknown_class_and_cross_class_costumes_are_refused_on_node_a_and_node_b() {
    let mut node_a = party();
    let mut node_b = party();
    let c = a_credit(b"costumes");
    let cm = c.note_cm().expect("cm");
    let need = node_a.required_stamp_bits();
    let mut bad_magic = c.wire();
    bad_magic[0] ^= 0x01;
    let mut unknown_class = c.wire();
    unknown_class[crate::chain_object::MAGIC.len()] = 0x7f;
    let cross_class =
        crate::chain_object::frame(crate::chain_object::Class::OrderFill, &c.encode());
    for (what, blob) in [
        ("wrong magic", bad_magic),
        ("unknown class byte", unknown_class),
        ("credit body under the OrderFill tag", cross_class),
    ] {
        let tx = retagged(c.as_pq_tx(need), blob, need);
        for (name, node) in [("node_a", &mut node_a), ("node_b", &mut node_b)] {
            let verdict = node.ingest_tx(tx.clone());
            assert!(
                verdict.is_err(),
                "{name}: FORGERY ({what}) must be refused at the door, got {verdict:?}"
            );
            assert!(!node.mempool().contains(&tx.id), "{name}: no pool slot for {what}");
            assert!(!node.holds_record_with_cm(&cm), "{name}: no record for {what}");
        }
    }
}

/// ⭐ RED-TEAM STAMP-AND-FRAME PIN — BARE postcard credit bytes on the OLD unframed path are judged
/// as an ordinary send and die at the send's ZK carrier gate, on BOTH independent nodes; and the
/// graft-side door on the receiving side (`apply_chain_bridge_credit`, node_b's reconcile half)
/// leaves the unframed bytes completely alone. The frame is the ONE wire encoding — the pre-8c bare
/// encoding must stay dead forever, or a dispatcher guess re-opens the cross-type decode ambiguity.
/// This pin goes RED if the unframed branch of `admissible` ever routes anywhere but the send
/// carrier gate.
#[test]
fn bare_unframed_credit_bytes_on_the_old_path_die_at_the_send_gate_on_node_a_and_node_b() {
    let mut node_a = party();
    let mut node_b = party();
    let c = a_credit(b"bare-postcard");
    let cm = c.note_cm().expect("cm");
    let need = node_a.required_stamp_bits();
    let tx = retagged(c.as_pq_tx(need), c.encode(), need);
    for (name, node) in [("node_a", &mut node_a), ("node_b", &mut node_b)] {
        let verdict = node.ingest_tx(tx.clone());
        assert!(
            matches!(verdict, Err(crate::mempool::MempoolError::InvalidProof)),
            "{name}: bare postcard bytes must die at the send's ZK carrier gate, got {verdict:?}"
        );
        assert!(!node.mempool().contains(&tx.id), "{name}: no pool slot for bare bytes");
        assert!(!node.holds_record_with_cm(&cm), "{name}: no record for bare bytes");
    }
    assert_eq!(
        crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit(&mut node_b, &c.encode()),
        CreditApply::NotCredit,
        "node_b's graft-side door must leave unframed bytes alone — the frame is the one encoding"
    );
}

/// One credit, one encoding — two nodes handed the same deposit must agree on its bytes and its id.
#[test]
fn a_credit_has_exactly_one_encoding() {
    let c = a_credit(b"canon");
    assert_eq!(c.encode(), c.encode(), "encoding must be deterministic");
    let back = BridgeCreditTx::decode(&c.encode()).expect("round trips");
    assert_eq!(back.encode(), c.encode(), "encode(decode(x)) != x");
    assert_eq!(back.note_cm(), c.note_cm(), "the commitment survives the round trip");
}

/// ⭐ PER-NOTE-VALIDITY PIN (2026-09-06, lane B) — THE CARRIAGE IS NOT THE OBJECT. A `PqTx` wrapper
/// whose `output_notes` differ from the notes its own framed object justifies is a mint costume:
/// the door verifies the BLOB (`chain_object::admissible`), but assembly and graft carry the
/// WRAPPER's notes — so a validly-framed credit blob with substituted or appended wrapper notes
/// mints arbitrary sealed value on every honest node, reachable by ANY submitter (gossip or RPC),
/// no modified producer needed. This is the deepest closable slice of the naked-chunk class: the
/// justification (blob) and the value carriage (output_notes) travel together on every path, so
/// binding them is judgeable at every door with nothing new on the wire.
///
/// ROOT-LAYER: `chain_object::wrapper_binds_object` — ONE rule at `ingest_tx` (both doors),
/// assembly, and the graft door, so the binding cannot drift between the seams.
/// MEASURED: first run 2026-09-06 decides RED or GREEN — a RED here is the CONFIRMED unbound-
/// carriage inflation hole and this pin is the specification of the binding fix.
/// MUST-STAY-GREEN: a_published_credit_lands_on_the_peer_and_a_replay_credits_nothing (the honest
/// wrapper still admits), and every pin in this suite.
#[test]
fn a_credit_wrapper_carrying_notes_the_object_does_not_justify_is_refused_on_node_a_and_node_b() {
    let mut node_a = party();
    let mut node_b = party();
    let c = a_credit(b"wrapper-bind");
    let need = node_a.required_stamp_bits();
    // Forgery 1 — SUBSTITUTION: the wrapper claims a different sealed note than the object's own.
    let mut foreign = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    foreign[..32].copy_from_slice(Hash32::hash(b"substituted-note").as_bytes());
    let mut sub = c.as_pq_tx(need);
    sub.output_notes = foreign.clone();
    // Forgery 2 — EXTENSION: the object's own note plus a naked extra note appended.
    let mut naked = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    naked[..32].copy_from_slice(Hash32::hash(b"naked-extra-note").as_bytes());
    let mut ext = c.as_pq_tx(need);
    ext.output_notes.extend_from_slice(&naked);
    let mut foreign_cm = [0u8; 32];
    foreign_cm.copy_from_slice(&foreign[..32]);
    let mut naked_cm = [0u8; 32];
    naked_cm.copy_from_slice(&naked[..32]);
    for (what, tx, cmx) in
        [("substituted wrapper note", &sub, &foreign_cm), ("appended naked wrapper note", &ext, &naked_cm)]
    {
        for (name, node) in [("node_a", &mut node_a), ("node_b", &mut node_b)] {
            let verdict = node.ingest_tx(tx.clone());
            assert!(
                verdict.is_err(),
                "{name}: FORGERY ({what}) — the wrapper's notes are not the object's notes and the \
                 door admitted it anyway ({verdict:?}); the carriage is unbound to the justification \
                 and this wrapper mints on every honest node"
            );
            assert!(
                !matches!(verdict, Err(crate::mempool::MempoolError::AlreadyKnown)),
                "{name}: the refusal must be the binding's own, never a stale by-id dedup ({what})"
            );
            assert!(!node.mempool().contains(&tx.id), "{name}: no pool slot for {what}");
            assert!(!node.holds_record_with_cm(cmx), "{name}: no record for {what}");
        }
    }
    // PRECONDITION-AS-POSTCONDITION: the HONEST wrapper (same blob, same id, the object's own note)
    // still admits on both doors — the binding refuses substitution, never the credit itself.
    node_a
        .ingest_tx(c.as_pq_tx(need))
        .expect("the honest wrapper must still admit on node_a — the binding must not overreach");
    node_b
        .ingest_tx(c.as_pq_tx(need))
        .expect("the honest wrapper must still admit on node_b — the binding must not overreach");
}

/// ⭐ PER-NOTE-VALIDITY PIN (2026-09-06, lane B) — task pin 1, the graft half: a ROGUE PRODUCER whose
/// modified binary injects a naked note chunk into a block it mines credits NOTHING for that chunk on
/// an honest peer that holds the block's carried transaction set, while the block itself still grafts
/// and every justified note still applies (fail-closed on the bad item, never the block).
///
/// The attack modelled: the rogue's produce is modified PAST its own assembly door, so the test
/// tampers the mined block body directly (append the naked chunk, re-seal `output_notes_root` — a
/// real rogue re-mines, which costs it nothing) and hands it to the peer through the preverified
/// graft entry. The peer holds the wrapper-poisoned tx in its pool via the test-only raw hook —
/// modelling bytes that reached a pool past the door, which is exactly what every pool held before
/// the binding existed. The graft door must judge the resolvable framed object and refuse the
/// wrapper chunks the object does not justify.
///
/// ROOT-LAYER: `Node::apply_grafted_block_carry`'s reconcile — the one seam where a block's carried
/// payload becomes node state on every graft path.
/// MEASURED: first run 2026-09-06 decides RED or GREEN — RED = the peer records and folds the
/// injected chunk (the confirmed residual), GREEN = the peer refuses the chunk and applies the rest.
/// ⛔ THE RESIDUAL THIS PIN DOES NOT CLOSE, stated so the claim is never wider than the mechanism: a
/// peer that does NOT hold the claiming tx body cannot attribute the block's chunks at all (the wire
/// carries no per-note justification), and folds them — see the chain_object module doc for the
/// remaining spec (id-bound carried justification, or the bonded-threshold arm).
/// MUST-STAY-GREEN: a_staged_credit_rides_the_next_block_and_lands_in_the_unspent_set,
/// an_idle_block_records_identical_bytes, a_published_credit_lands_on_the_peer_and_a_replay_credits_nothing.
#[test]
fn a_rogue_producers_injected_chunk_credits_nothing_on_a_peer_holding_the_carried_set() {
    let mut node_a = party(); // the rogue producer
    let mut node_b = party(); // the honest peer
    let c = a_credit(b"graft-injection");
    let credit_cm = c.note_cm().expect("cm");
    let bits = node_a.required_stamp_bits();
    // The wrapper the rogue pools carries the object's note PLUS a naked extra chunk. Raw admission
    // on BOTH nodes: the rogue's binary has no door, and the peer's pool models bytes admitted
    // before the binding existed (or through any door hole) — the graft door must still refuse.
    let mut naked = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    naked[..32].copy_from_slice(Hash32::hash(b"rogue-injected-chunk").as_bytes());
    let mut naked_cm = [0u8; 32];
    naked_cm.copy_from_slice(&naked[..32]);
    let mut poisoned = c.as_pq_tx(bits);
    poisoned.output_notes.extend_from_slice(&naked);
    // ⭐ DB-224 — THE ROGUE'S OWN POOL HOLDS THE HONEST WRAPPER (the same tx id: the blob is the honest
    // object either way). Its assembly therefore carries the credit's note AND the object's carriage —
    // the carried set may only name notes the block itself commits (the subject rule), so a rogue whose
    // block the chain would even accept has to carry them together. It then injects the naked chunk
    // below. (The first model pooled the POISONED wrapper on the rogue too: its own assembly refused it,
    // the note never rode, and the object — correctly — no longer rides the carried set either, so the
    // welded-back note had no justification left: a model of a block no honest peer's rules produce.)
    node_a
        .ingest_tx_unverified(c.as_pq_tx(bits))
        .expect("the rogue's own pool takes the wrapper raw — that is the attack model");
    node_b
        .ingest_tx_unverified(poisoned)
        .expect("the peer's pool holds the POISONED bytes — resolvable at graft, judgeable at graft");
    let now = node_a
        .dag()
        .get(&node_a.selected_tip().expect("tip"))
        .expect("hdr")
        .header
        .timestamp
        + node_a.params().target_spacing_ms;
    let mut blk = node_a
        .produce(now, Hash32::hash(b"rogue-inject"), Hash32::hash(b"rogue-inject-m"))
        .expect("the rogue produces");
    // The rogue's modified produce: the object's justified note rode its honest assembly (and its
    // carriage rides the carried set); the rogue welds the INJECTED naked chunk into the body itself
    // and re-seals the note root (a real attacker re-mines the tampered header; PoW is orthogonal to
    // what is pinned here, so the preverified graft entry stands in for the re-mine).
    if !blk
        .output_notes
        .chunks(crate::cover::PQ_NOTE_BYTES)
        .any(|ch| ch.len() >= 32 && ch[..32] == credit_cm)
    {
        blk.output_notes.extend_from_slice(&c.note);
    }
    if !blk
        .output_notes
        .chunks(crate::cover::PQ_NOTE_BYTES)
        .any(|ch| ch.len() >= 32 && ch[..32] == naked_cm)
    {
        blk.output_notes.extend_from_slice(&naked);
    }
    blk.header.output_notes_root = crate::block::da_notes_root_of(&blk.output_notes);
    assert!(
        blk.output_notes
            .chunks(crate::cover::PQ_NOTE_BYTES)
            .any(|ch| ch.len() >= 32 && ch[..32] == naked_cm),
        "PRECONDITION: the rogue block genuinely carries the injected chunk"
    );
    let out = node_b.ingest_block_preverified(blk, now + 500);
    let holding: Vec<u64> = node_b
        .records_containing_cm(&naked_cm)
        .iter()
        .map(|(rid, _, _)| *rid)
        .collect();
    assert!(
        !node_b.holds_record_with_cm(&naked_cm),
        "CONFIRMED FUNDS-SAFETY RESIDUAL: the honest peer recorded a naked chunk no admitted \
         object in the block's carried set justifies (graft outcome {out:?}; record addr(s) \
         holding it: {holding:?}) — a rogue producer mints through the block body on every peer \
         that can resolve the carriage"
    );
    assert!(
        node_b.holds_record_with_cm(&credit_cm),
        "OVERREACH: the justified credit note must still apply on the peer — fail-closed on the \
         bad item, never the block (graft outcome {out:?})"
    );
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// ⛔⛔⛔ DOOR AUDIT 2026-09-07, FAMILY B, §9.6 QUESTIONS 2, 3 AND 4. THIS IS A FIX SPEC.
//
// THE MECHANISM. `apply_grafted_block_carry` (node.rs:18400) runs TWO loops over the SAME pooled
// blobs of a grafting block:
//   * node.rs:18473 → `graft_admitted_notes` → `chain_object::admissible` (node.rs:18336). A
//     framed object the class rule refuses has ALL its wrapper note cms STRIPPED: its value does
//     not land. That is the mint-authority door and it holds.
//   * node.rs:18545-18553 → `apply_chain_bridge_credit` over `self.mempool.get(id).blob` for
//     EVERY tx id in the block, with NO `admissible` filter and no consultation of what the first
//     loop just refused.
// The second loop's only effect on state is `node.unstage_credit_note(&cm)`
// (bridge_credit_tx.rs:190), and `unstage_credit_note` (node.rs:1633-1638) is a pure `retain` on
// the 32-byte commitment — it asks nothing about whether a published copy actually LANDED.
//
// SO THE REFUSAL AND THE DESTRUCTION DISAGREE. A framed credit whose notes the graft door refused
// still destroys the honest staged credit that shares its commitment: the published copy never
// lands (stripped) and the staged copy is dropped (retained away). The credit then exists
// NOWHERE — it is not on chain and it is no longer queued to ride any block. `stage_credit_note`
// is the lane every faucet drip, publish-refused peg-in, unbond return, executor credit and
// stranded-note re-carry rides (chain_object.rs:65-67), so this is a funds-DESTRUCTION door, not
// a mint one.
//
// THE COMMITMENT IS NOT A SECRET AND NOT A CAPABILITY. `/faucet/drip` returns the issued note in
// full in its own response body (rpc_http.rs:1006, `"note":"<hex>"`, and `"staging_id"` is the
// cm itself), and a published credit carries its note on the wire. Naming a cm therefore proves
// nothing about holding it, yet naming one is the whole authority this door asks for.
//
// THE FIX SPEC (one shared site, per §9.5): the reconcile loop must consume the SAME filtered
// verdict the note loop produced, not the raw pool blobs — i.e. `apply_chain_bridge_credit` is
// called only for blobs `chain_object::admissible` accepted (the `graft_admitted_notes` helper
// already computes exactly that set and exists precisely so a second writer cannot drift from
// it — see its own doc at node.rs:18304-18311, which records this identical "the record path
// re-recorded what the door had stripped" failure). Stronger and preferable, because it makes
// the destruction follow the arrival rather than the announcement: unstage only for a cm this
// node can SEE in the grafting block's ADMITTED note bytes — one containment test against bytes
// already in hand at that line, no new store and no new lookup.
// ────────────────────────────────────────────────────────────────────────────────────────────

/// ⛔ PIN B-4 (RED = CONFIRMED HOLE). Two independent parties. Each has an honest credit STAGED to
/// ride its next block. A framed credit naming the SAME commitment but an amount this chain's
/// genesis-derived allowance forbids — the exact object `chain_object::admissible` refuses by
/// name, so its own notes can never land — is handed to the graft-side reconcile door. The
/// staged credit must survive on BOTH parties: a refused object must not be able to retire it.
#[test]
fn a_credit_the_mint_door_refuses_cannot_retire_a_staged_credit_on_either_party() {
    let honest_note = vec![0x5Au8; crate::cover::PQ_NOTE_BYTES];
    let cm: [u8; 32] = honest_note[..32].try_into().expect("32-byte prefix");

    // The forgery: same commitment, an amount beyond the chain's open-mint allowance. Its notes
    // are stripped at the graft door (`admissible` false), so nothing it claims can ever land.
    let forged = BridgeCreditTx {
        deposit_id: [77u8; 32],
        asset_tag: [0, 0, 0],
        amount: crate::params::TESTNET_OPEN_MINT_ALLOWANCE + 1,
        note: honest_note.clone(),
        owner_clue: Vec::new(),
        attestors: Vec::new(),
    };
    assert!(
        !crate::chain_object::admissible(
            &forged.wire(),
            ChainParams::default().order_fill_fee_bps,
            crate::params::TESTNET_OPEN_MINT_ALLOWANCE,
            false
        ),
        "PRECONDITION: the mint-authority door refuses this object, so its notes never land"
    );

    for name in ["node_a", "node_b"] {
        let mut node = party();
        node.stage_credit_note(honest_note.clone());
        assert!(
            node.holds_staged_credit(&cm),
            "{name}: PRECONDITION — the honest credit is staged to ride the next block"
        );
        let verdict = crate::node::objects::bridge_credit_tx::apply_chain_bridge_credit(&mut node, &forged.wire());
        assert!(
            node.holds_staged_credit(&cm),
            "⛔ HOLE on {name}: the graft-side reconcile door retired a STAGED credit on the \
             word of an object the mint-authority door refuses (verdict {verdict:?}). The \
             refused object's own note is stripped by `graft_admitted_notes`, so the published \
             copy never lands — and now the staged copy is gone too. The credit exists nowhere. \
             `unstage_credit_note` is keyed on a 32-byte commitment that `/faucet/drip` hands \
             to its own caller in clear, so naming it proves nothing about holding it."
        );
    }
}
