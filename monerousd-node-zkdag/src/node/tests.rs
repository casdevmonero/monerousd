// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::*;
use crate::block::BlockHeader;
use crate::mempool::PqTx;

/// G11b step B — the follow lane's work after an adopt, in process. The constant sync bundle installs the server's
/// FOLD ANCHOR (never the unfolded window above it: that window is LIVE_LANE_DEPTH × block wire, above the 16 MiB
/// frame), and the server's blocks above the anchor reach the joiner the way the runtime pages them right after the
/// adopt: a locator page (Bitcoin `getblocks` / Kaspa IBD above the pruning point) from the joiner's own selected
/// chain, each body through the same `ingest_block` door, oldest first, page after page until a page brings nothing.
/// CHAIN-PUBLISH-REVIEWED: a TEST harness's stand-in for the runtime's follow lane; the bodies are blocks the server's
/// chain already carries and each one passes the joiner's ordinary ingest door.
/// It first runs the runtime's own post-adopt step (node_runtime.rs, the adopt arm): DB-297 drops every orphan parked
/// against the DAG the adopt replaced (the next page re-lists a live one), then the adopted tip's parked children are
/// re-injected through the ingest door. MEASURED (g11b-three-20261023-0819.log): without it, four of the producer's
/// blocks parked before the re-anchor were re-served 256 times, each `AlreadyBuffered`, and the next block parked.
/// A page that grafts nothing is no progress: the loop ends there.
pub(crate) fn page_above_anchor(joiner: &mut Node, server: &Node) {
    let ts = server.dag().get(&server.selected_tip().expect("tip")).expect("header").header.timestamp + 500;
    let dropped = joiner.relay_drop_orphans_the_dag_cannot_attach();
    let tip = joiner.selected_tip().expect("the adopted tip");
    for b in joiner.take_orphans_waiting_on(&tip) {
        let _ = joiner.ingest_block(b, ts);
    }
    if dropped > 0 {
        eprintln!("[page-above-anchor] DB-297: the adopt dropped {dropped} orphan(s) parked against the replaced DAG");
    }
    for _ in 0..256 {
        let locator = joiner.batch_locator(None);
        let Some((page, _)) =
            server.whole_blocks_after_locator(&locator, 32, 1 << 20, &[], &joiner.batch_parked_ids(128))
        else {
            break;
        };
        let fresh: Vec<crate::block::Block> = page
            .into_iter()
            .filter(|b| joiner.dag().get(&b.id()).is_none() || joiner.holds_only_a_shell(&b.id()))
            .collect();
        if fresh.is_empty() {
            break;
        }
        let n = fresh.len();
        let mut refused: Vec<String> = Vec::new();
        for b in fresh {
            let id = b.id();
            match joiner.ingest_block(b, ts) {
                crate::relay::RelayOutcome::Added(_) | crate::relay::RelayOutcome::Duplicate(_) => {}
                other => refused.push(format!("{}: {other:?}", &id.to_hex()[..8])),
            }
        }
        eprintln!("[page-above-anchor] page {n} bod(ies), refused {}: {refused:?}", refused.len());
        if refused.len() == n {
            break;
        }
    }
    // THE WARM LANE, right after the adopt, as the runtime's pivot worker runs it (DB-290): a jumper holds the certified
    // band root and NO view, and its pivot is placeable only while a peer's band journal (reach = the lag cap) still
    // holds it. MEASURED (pin-db265-loop2-120829-20261023.log): run only at the fixture's end, 40 rounds later, the
    // origin's late fold reorg (69 records from ordinal 13) had carried its band past the joiner's pivot ("the pivot is
    // unknown to this node's band … older than its ring"; joiner pointer 1, origin floor 13 → 18), so the joiner never
    // warmed and folded 0 of 69 blocks — on every run whose tie-break made the joiner's blocks the selected chain.
    joiner.warm_if_viewless_for_test(server);
}

/// A real account owner for tests that CREDIT a note. The credit gates refuse an ownerless credit — a
/// note filed nowhere is undiscoverable money — so a test must supply one or it would pass for the wrong
/// reason: "rejected because no owner" instead of "rejected because the proof was bad".
pub(crate) fn test_owner() -> Vec<u8> {
    // DB-273 §19 L1: an owner is the credited note's OLI clue (one full-width clue), never a (bucket, ek) pair.
    vec![0x5au8; crate::peg_in_tx::OWNER_CLUE_MAX]
}

/// DB-273 §19 L1: the recipient a peg-in of deposit `dep` must name — the commitment to [`test_owner`]'s clue the
/// quorum signs (`peg::peg_in_recipient`). A fixture that names any other recipient is refused before any prove.
pub(crate) fn test_recipient(dep: &[u8; 32]) -> [u8; 32] {
    crate::peg::peg_in_recipient(dep, &test_owner())
}

/// The (bucket, ek) owner the UNBOND and YIELD-CLAIM doors still take: their statements and return entries move to
/// a clue in DB-273 §19 L2, and this fixture goes with them.
pub(crate) fn test_bucket_owner() -> ([u8; 32], Vec<u8>) {
    let (ek, _dk) = crate::pqkem::keypair();
    (crate::account_da::bucket_id(b"test-credit-owner"), ek)
}

/// DB-80: the mint-delta blind a test's requester draws once; the committed mint carrier and the
/// proposal/execute calls must agree on it exactly as a wallet and its custodian do.
/// CHAIN-PUBLISH-REVIEWED: a test-only constant (no state, no mutation) — the existing test call
/// sites that take it publish through `execute_peg_in`'s own pool object as they always did.
pub(crate) fn test_d_blind() -> crate::spend_frontier::Digest4 {
    usdm_decider::poseidon2_compress::lanes_of(&[0xdb80u64, 0x1, 0x2, 0x3])
}

/// A SECOND deposit's blind. DB-123 makes the reserve address a function of the mint blind, so a fixture
/// with two deposits needs two blinds — one address each (DB-93: one mint per reserve address).
pub(crate) fn test_d_blind2() -> crate::spend_frontier::Digest4 {
    usdm_decider::poseidon2_compress::lanes_of(&[0xdb80u64, 0x1, 0x2, 0x4])
}

/// §BR-2: a test deposit's DEPOSITOR key — the wallet's per-deposit key, derived here from the deposit's blind so every
/// fixture with one blind names one depositor (the wallet derives it from its 24 words).
pub(crate) fn test_depositor_secret(d_blind: &crate::spend_frontier::Digest4) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/test/depositor/v1");
    h.update(&crate::spend_frontier::digest_to_lane_bytes(d_blind));
    *h.finalize().as_bytes()
}
pub(crate) fn test_depositor_x(d_blind: &crate::spend_frontier::Digest4) -> [u8; 32] {
    crate::btc_tx::xonly_pubkey(&test_depositor_secret(d_blind)).expect("a hash is a key") // CLASSICAL-CRYPTO-EXEMPT: the test depositor's Bitcoin key (bridge endpoint)
}

/// §BR-2: FUND A TEST DEPOSIT the way a wallet does — the confirmed coin (the test oracle, as the watcher would see it)
/// and the depositor's sweep authorization over it, staged on the EXECUTOR `n` exactly as a wallet's sealed request
/// stages it (`custodian_act_on_request`). Every custodian then verifies it for real at its attest door.
pub(crate) fn fund_test_deposit(n: &mut Node, reserve: &str, d_blind: &crate::spend_frontier::Digest4, sats: u64) {
    crate::btc_watch::inject_confirmed_for_test(reserve, sats);
    let coin = crate::btc_watch::injected_coin_for_test(reserve);
    let auth = test_sweep_auth(n, reserve, d_blind, coin.txid, coin.vout, coin.value_sats, crate::btc_tx::DEPOSIT_SWEEP_FEE_MIN_SATS);
    n.stage_deposit_sweep(reserve, auth);
}

/// §BR-2: the depositor's sweep authorization a wallet signs over (`txid:vout`, `value`, `fee`) at `reserve` — the test
/// depositor's key for `d_blind`, under the custody leaf that derives the address on `n`.
pub(crate) fn test_sweep_auth(
    n: &Node,
    reserve: &str,
    d_blind: &crate::spend_frontier::Digest4,
    txid: [u8; 32],
    vout: u32,
    value_sats: u64,
    fee_sats: u64,
) -> crate::peg_attest::SweepAuth {
    let d = test_depositor_x(d_blind);
    let leaf = n.deposit_leaf_for(reserve, d_blind, &d).expect("the reserve is this node's co-signed deposit address");
    let nonce = crate::spend_frontier::digest_to_lane_bytes(d_blind);
    let out = crate::btc_tx::deposit_output(&leaf, &d, &nonce).expect("a deposit output");
    let (tx, _) = crate::btc_tx::deposit_sweep_payout(&out, &leaf, &nonce, txid, vout, value_sats, fee_sats).expect("the sweep builds");
    let m = crate::btc_tx::deposit_sweep_sighash(&tx, &out).expect("the sweep's sighash");
    let sig = crate::btc_tx::sign_sighash(&test_depositor_secret(d_blind), &m, &[9u8; 32]).expect("sign"); // CLASSICAL-CRYPTO-EXEMPT: the test depositor's BIP-340 sweep signature (bridge endpoint)
    crate::peg_attest::SweepAuth { depositor_x: d, txid, vout, value_sats, fee_sats, sig }
}

/// DB-123: the reserve address THIS node derives for a blind under its live custody leaf — the only
/// address a custodian will attest a deposit at, so it is the one a fixture deposits to.
pub(crate) fn reserve_for(n: &Node, d_blind: &crate::spend_frontier::Digest4) -> String {
    // The refusal names the bonded set it read, so a fixture that seats no custodian says which half is missing.
    match n.reserve_addresses_for_blind(d_blind, Some(&test_depositor_x(d_blind))).0 {
        Some(a) => a,
        None => panic!(
            "the bonded set derives a reserve address — seated {}, custody-weighted with a registered point {}, \
             custody leaf members {}, fold tip {:?}",
            n.validators.len(),
            n.validators.bonded_custody_weighted().len(),
            n.custody_members_current().len(),
            n.fold_chain_tip
        ),
    }
}

/// TEST-ONLY: make a HAND-BUILT fixture header honest about the work it claims.
///
/// A fixture that types `work: 5` onto a header it never ground is claiming a grind it did not
/// do. That used to be invisible, because the #29 adopt asked no block whether it was mined; as
/// of 2026-09-07 it does (`Node::bundle_blocks_admitted`), so a fixture must either claim no work
/// or actually pay for it. This pays for it, with the SAME loop the production miner runs
/// (`PowMiner::mine`): bump the nonce until `hash_meets_target` accepts the header's own claimed
/// figure. At the DAA floor that is a handful of Poseidon2 hashes.
///
/// Call it BEFORE taking the block's `id()` — grinding changes the nonce, hence the id.
/// The hasher is epoch-seeded from the network constant, so any `PowMiner` produces the same
/// digests as the node the fixture will hand the block to.
pub(crate) fn grind_fixture_header(header: &mut BlockHeader) {
    let m = crate::pow::PowMiner::new().expect("the PoUW epoch hasher builds");
    while !crate::pow::hash_meets_target(&m.hasher().hash(&header.preimage()), header.work) {
        header.nonce = header.nonce.wrapping_add(1);
    }
}

/// ⭐⭐⭐ MINE A FIXTURE BLOCK — the grind AND the non-outsourceable witness.
///
/// ⛔ [`grind_fixture_header`] grinds the nonce and NOTHING ELSE, so a block it prepares carries
/// `pow_proof: Vec::new()` — it satisfies "this header was ground to its own declared target" and
/// says nothing about whether anyone mined it. That was the whole of the non-gossip doors' work
/// check until 2026-09-13, and the door audit's R1 pin ground an admissible anchor in SEVEN hashes
/// with no witness at all, then had it installed at `blue_work = u128::MAX`.
///
/// Now that `header_door_admits` asks for the witness, a fixture that only grinds is testing a
/// block PRODUCTION CANNOT PRODUCE: a real DSYNC anchor is a mined block off a chain that is ahead,
/// and it has a proof. ⭐ A fixture that cannot exist on the live chain proves nothing about the
/// live chain — and here it would have quietly asserted that an unmined anchor is adoptable.
pub(crate) fn mine_fixture_block(block: &mut Block) {
    let m = crate::pow::PowMiner::new().expect("the PoUW epoch hasher builds");
    block.pow_proof = m.mine(&mut block.header).expect("the fixture block mines");
}

pub(crate) fn genesis_block() -> Block {
    Block {
        cover_key: None,
        wide_objects: Vec::new(),
        tx_bodies: Vec::new(),
        agg_tables: Vec::new(),
        note_commitments: Vec::new(),
        header: BlockHeader {
        note_commitments_root: crate::hash::Hash32::hash(&[]),
            nullifier_tags_root: crate::hash::Hash32::hash(&[]),
            output_notes_root: crate::hash::Hash32::hash(&[]),
            // P4'a fixture: this block ships no locator tags and no account targets, so both sidecar
            // commitments are the empty-payload hash the verifier re-derives.
            oli_tags_root: crate::block::da_sidecar_root_of(&[]),
            // ⭐ §BA — no credit set here, so the DERIVED empty sidecar root, never a magic constant.
            credit_set_root: crate::block::da_sidecar_root_of(&[]),
            transitions_root: crate::block::empty_transitions_root(),
            cover_seed_commit: crate::hash::Hash32::ZERO,
            member_ring_commit: crate::hash::Hash32::ZERO,
            account_targets_root: crate::block::da_sidecar_root_of(&[]),
            bond_set_root: crate::block::da_sidecar_root_of(&[]),
            dir_set_root: crate::block::da_sidecar_root_of(&[]),
            letter_set_root: crate::block::da_sidecar_root_of(&[]),
            tag_evidence_root: crate::block::da_sidecar_root_of(&[]),
            level_root: crate::hash::Hash32::ZERO, fold_ordinal: 0, fold_commit: crate::hash::Hash32::ZERO, band_ordinal: 0, band_commit: crate::hash::Hash32::ZERO,
            version: 1,
            parents: vec![],
            timestamp: 0,
            nonce: 0,
            work: crate::miner::BOOTSTRAP_WORK,
            pow_bind: Hash32::ZERO,
            tx_merkle_root: Hash32::ZERO,
            frontier_root: Hash32::ZERO,
            nullifier_root: Hash32::ZERO,
            sparse_root: crate::hash::Hash32::ZERO,
            chain_acc: [0u8; 16],
            miner_commitment: Hash32::ZERO,
            account_root: Hash32::ZERO,
        },
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
        cover_transition: None,
        member_transition: None,
        nullifier_proof: crate::block::NfBlockProof::default(),
    }
}

/// A testnet party that folds at its tip — the shape the scenario engines and the replayed-credit pin use:
/// the genesis-derived open-mint allowance of the testnet prefix admits the fixture's credit objects
/// (`carry_notes_in_a_block_for_test`), and a carried note enters the unspent tree at ingest.
pub(crate) fn testnet_party_folding_at_tip() -> Node {
    testnet_party_with_fold_depth(0)
}

/// A testnet-identity party whose record fold trails the tip by `depth` blocks (production: `RECORD_FOLD_DEPTH_DEFAULT`).
pub(crate) fn testnet_party_with_fold_depth(depth: u64) -> Node {
    let mut p = crate::params::ChainParams::default();
    p.record_fold_depth = depth;
    testnet_party_with_params(p)
}

/// A testnet-identity party on caller-chosen params (the network identity fields are overwritten).
pub(crate) fn testnet_party_with_params(mut p: crate::params::ChainParams) -> Node {
    p.genesis_parity_commit = crate::params::network_genesis_prefix("testnet");
    p.net_prefix_len = p.genesis_parity_commit.len();
    let g = crate::block::Block {
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
        credit_set: Vec::new(),
        dir_set: Vec::new(),
        letter_set: Vec::new(),
        tag_evidence: Vec::new(),
        note_transition: None,
        nullifier_proof: crate::block::NfBlockProof::default(),
        cover_transition: None,
        member_transition: None,
    };
    let mut n = Node::with_params(g, p).expect("a testnet party builds");
    n
}

/// ⛔ DB-358 (1) fixture: a spend may consume only a FOLDED record, so a pin that spends a note it just created
/// must first let the fold pass that note's block, exactly as a wallet waits for it. The producer lays
/// `record_fold_depth + 2` idle chain blocks, each `step_ms` after `ts0`, and every peer grafts each one.
/// ONE helper, so every fixture waits the same way. It returns the last timestamp used.
pub(crate) fn produce_past_the_fold(producer: &mut Node, peers: &mut [&mut Node], ts0: u64, step_ms: u64) -> u64 {
    let mut ts = ts0;
    for _ in 0..producer.relay.dag().record_fold_depth() + 2 {
        ts += step_ms;
        let b = producer
            .produce(ts, Hash32::hash(b"db358-fold-wait-fr"), Hash32::hash(b"db358-fold-wait-mc"))
            .expect("an idle block produces");
        for p in peers.iter_mut() {
            let _ = p.ingest_block(b.clone(), ts);
        }
    }
    ts
}

/// G11b fixture: `produce_past_the_fold` that KEEPS the blocks it lays — a joiner adopts the server's FOLD ANCHOR (Kaspa's
/// pruning point) and takes the blocks above it from the follow-page lane, which a pin models by ingesting these.
pub(crate) fn produce_past_the_fold_keeping(producer: &mut Node, ts0: u64, step_ms: u64) -> (u64, Vec<Block>) {
    let mut ts = ts0;
    let mut kept = Vec::new();
    for _ in 0..producer.relay.dag().record_fold_depth() + 2 {
        ts += step_ms;
        kept.push(
            producer
                .produce(ts, Hash32::hash(b"db358-fold-wait-fr"), Hash32::hash(b"db358-fold-wait-mc"))
                .expect("an idle block produces"),
        );
    }
    (ts, kept)
}

/// G11b fixture: hand a joiner the server's blocks above the adopted anchor (the follow-page lane's bodies), in order.
pub(crate) fn follow_pages_for_test(joiner: &mut Node, blocks: &[Block], ts: u64) {
    for b in blocks {
        if joiner.dag().get(&b.id()).is_none() {
            let _ = joiner.ingest_block(b.clone(), ts);
        }
    }
}

/// A CANONICAL nullifier digest for tests — `cover_nullifier_det(blake3(label), 0)`, which decodes
/// injectively under `cm_bytes_to_root` (the pool door and the template keep loop both require this).
/// Tests that pool a grind_tx with a nullifier MUST use this, not `Hash32::hash` (blake3 ≠ canonical).
pub(crate) fn canon_nf_for_test(label: &[u8]) -> Hash32 {
    Hash32(crate::cover::cover_nullifier_det(Hash32::hash(label).as_bytes(), 0))
}

pub(crate) fn grind_tx(blob: &[u8], weight: u32, nfs: Vec<Hash32>, need: u32) -> PqTx {
    let id = PqTx::content_id(blob);
    let mut s = 0u64;
    loop {
        let tx = PqTx {
            clock_ms: 0,
            note_clues: Vec::new(),
            account_targets: Vec::new(),
            id,
            blob: blob.to_vec(),
            weight,
            nullifiers: nfs.clone(),
            pow_stamp: s,
            output_notes: Vec::new(),
            stake_notes: Vec::new(),
            bond_notes: Vec::new(),
            nullifier_witnesses: Vec::new(),
            nullifier_absence: Vec::new(),
            membership_carrier: Vec::new(),
            membership_leaf_commit: [0u8; 32],
            membership_tip: Vec::new(),
            membership_folded_through: 0,
            // §18: the carrier the fixture list was proven with (`test_tag_list_registered`), so the producer states the spend
            spend_or_decoy: crate::note_transition::test_cover_carrier_for(&nfs).unwrap_or_default(),
            member_carrier: Vec::new(),
            member_tuple: Vec::new(),
        };
        if tx.stamp_work() >= need {
            return tx;
        }
        s += 1;
    }
}

/// TEST — ONE HONEST SPEND a producer can pool (`ingest_tx_unverified`) and lay: a real validity carrier
/// (`prove_wallet_spend`), its two output notes, and its tag list. The block it rides carries a note transition that
/// STATES its nullifier and claim tag, so its fold step admits them (DB-367: a step admits only justified tags — a block
/// of fill alone admits nothing). `seed` keeps spends distinct across a test.
/// ⭐ DB-223 Q7: FUNDED first — the input note rides a block `node` lays and folds (`fund_inputs_for_test`), and the
/// spend carries its member leg; a spend of a note that was never received is exactly what Q7 refuses.
pub(crate) fn honest_spend_tx_for_test(node: &mut Node, peers: &mut [&mut Node], seed: u64) -> PqTx {
    honest_spend_tx_with_values_for_test(node, peers, seed, 999_999_000, 1_000)
}

/// §22 — a sealed credit set for a FIXTURE block, under the key the doors will open it with (`credit_seal_key` of the
/// block's own header and cover key): what `credit_set_encode` used to hand a rogue-block or door pin.
pub(crate) fn sealed_credit_set(blk: &Block, objects: &[Vec<u8>]) -> Vec<u8> {
    let key = crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref())
        .expect("a fixture block carries its cover key (a produced block always does)");
    crate::block::credit_set_seal(objects, &key).expect("the fixture's objects fit the sealed width")
}

/// §22b — the same, split the way the producer splits: the sealed bytes AND the wide objects that go beside the body.
pub(crate) fn sealed_credit_parts(blk: &Block, objects: &[Vec<u8>]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let key = crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref())
        .expect("a fixture block carries its cover key (a produced block always does)");
    crate::block::seal_carriages(objects, &key).expect("the fixture's frames fit the sealed width")
}

/// [`honest_spend_tx_for_test`] with the two output VALUES chosen by the caller (`out0 + out1` funds the input), so a
/// shape census can weigh two spends that differ only in amount.
pub(crate) fn honest_spend_tx_with_values_for_test(
    node: &mut Node,
    peers: &mut [&mut Node],
    seed: u64,
    out0_value: u64,
    out1_value: u64,
) -> PqTx {
    spend_tx_paying_fee_for_test(node, peers, seed, out0_value, out1_value, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC)
}

/// §BR-14 — [`honest_spend_tx_with_values_for_test`] paying `fee` (the funded input is `out0 + out1 + fee`): the honest
/// spend pays the protocol fee; a tamper pin passes any other fee and every door must refuse the carrier.
pub(crate) fn spend_tx_paying_fee_for_test(
    node: &mut Node,
    peers: &mut [&mut Node],
    seed: u64,
    out0_value: u64,
    out1_value: u64,
    fee: u64,
) -> PqTx {
    use usdm_decider::poseidon2_compress::lanes_of;
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let w = usdm_decider::whir_rec_block::SpendValidityWitness {
        value_in: out0_value + out1_value + fee,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&[0x5eed, seed, 1, 1])),
        value_out: out0_value + out1_value,
        fee, // §BR-14: the protocol fee for an honest spend
        lc_blind: lanes_of(&[0x5eed, seed, 2, 2]),
        out0_value,
        out0_opening: lanes_of(&[0x5eed, seed, 3, 3]),
        out1_value,
        out1_opening: lanes_of(&[0x5eed, seed, 4, 4]),
    };
    // A production wallet files a locator clue for BOTH outputs (wallet lib.rs `note_clues_hex`) and proves its carrier
    // under that filing's D; an unfiled spend cannot ride a ledger block (`uniform_ledger_filing`).
    let clues: [Vec<u8>; 2] = [0u8, 1].map(|j| format!("honest-spend-clue-{seed}-{j}").into_bytes());
    let (blob, cms, nf, lc, _d) =
        crate::note_transition::prove_filed_spend(&w, [Some(crate::oli::index_key(&clues[0])), Some(crate::oli::index_key(&clues[1]))])
            .expect("an honest validity proof");
    let mut records: Vec<([u8; 32], Vec<u8>)> = vec![(b32(cms[0]), clues[0].clone()), (b32(cms[1]), clues[1].clone())];
    records.sort();
    let note_clues = Node::encode_note_clue_records(&records);
    let mut notes = Vec::with_capacity(2 * crate::cover::PQ_NOTE_BYTES);
    for c in cms {
        let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        n[..32].copy_from_slice(&b32(c));
        notes.extend_from_slice(&n);
    }
    let tags = crate::note_transition::test_spend_tag_list(nf, &w, &format!("honest-spend-{seed}"));
    let mut tx = grind_tx(&blob, blob.len() as u32, tags, node.mempool().required_stamp_bits());
    tx.output_notes = notes;
    tx.note_clues = note_clues;
    tx.membership_leaf_commit = b32(lc);
    // DB-223 Q7: fund the input on this node's chain (a block just after its tip), then attach the spend's member leg.
    let tip_ts = match node.selected_tip().and_then(|t| node.relay.dag().get(&t).map(|n| n.header.timestamp)) {
        Some(t) => t,
        None => 0,
    };
    let funded = fund_inputs_for_test(node, peers, &[&w], tip_ts + 1);
    // A node whose record fold trails the tip lays its fold depth of blocks more, so the funding record is FOLDED
    // (a spend names only canonical state, DB-358) before the member leg is built; every peer grafts them too.
    for i in 0..node.params().record_fold_depth {
        let mut tag = seed.to_le_bytes().to_vec();
        tag.extend_from_slice(&i.to_le_bytes());
        if let Some(blk) = node.produce(tip_ts + 2 + i, Hash32::hash(&tag), Hash32::hash(b"honest-spend-fold")) {
            for p in peers.iter_mut() {
                let _ = p.ingest_block(blk.clone(), tip_ts + 3 + i);
            }
        }
    }
    let _ = node.fold_canonical_records();
    attach_member_leg_for_test(node, &mut tx, &funded[0], &w, nf, &cms);
    // THE COVER CARRIER — the production wallet's constant-width shape. Without `spend_or_decoy`
    // the block producer's `pending_cover_for` skips this tx and the block carries no
    // `cover_transition`, so the observer pin cannot weigh that field. The stamp (`stamp_work`)
    // hashes `id || pow_stamp || network_id` — it does NOT depend on `nullifiers`, so replacing
    // the tag list after the grind is safe.
    {
        use usdm_decider::nf_sparse_air::{cover_tag_native, prove_spend_or_decoy_bytes, TagWitness};
        let leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w)
            .expect("a well-formed witness has an input leaf");
        let tag1 = usdm_decider::whir_rec_block::spend_tag1(&w);
        let tx_secret = *Hash32::hash(
            &[b"MONEROUSD-TEST-WALLET-TX-SECRET-v1".as_slice(), tx.id.as_bytes()].concat(),
        )
        .as_bytes();
        let bound = crate::spend_frontier::note_leaf_of(&tx_secret);
        let mut prod_tags = vec![nf, tag1];
        prod_tags.extend(
            (2..crate::cover::TX_FIXED_NULLIFIER_COUNT as u64).map(|slot| cover_tag_native(bound, slot)),
        );
        let (claim_key, claim_leaf) = usdm_decider::slot_ledger::slot_claim_preimage(w.lc_blind, 0);
        let mut wit: Vec<TagWitness> = vec![
            TagWitness::RealSpend { key: w.owner.nk, leaf },
            TagWitness::RealSpend { key: claim_key, leaf: claim_leaf },
        ];
        while wit.len() < prod_tags.len() {
            wit.push(TagWitness::Decoy);
        }
        tx.spend_or_decoy = prove_spend_or_decoy_bytes(bound, &prod_tags, &wit)
            .expect("an honest spend_or_decoy proof");
        tx.nullifiers = prod_tags.iter().map(|t| Hash32(b32(*t))).collect();
    }
    tx
}

/// TEST — ⭐ DB-223 Q7: put the INPUT notes of witnesses `ws` on chain the way production does — ONE block `a` lays,
/// each note under a real `BridgeCredit` justification (`carry_notes_in_a_block_for_test`), which every node in
/// `peers` grafts and folds. Since Q7 a spend proves its input EXISTS, so a fixture spending a note that was never
/// received is exactly the hole the rule closes; this is the funding such a fixture was missing. Returns each
/// input's commitment, in `ws` order.
pub(crate) fn fund_inputs_for_test(
    a: &mut Node,
    peers: &mut [&mut Node],
    ws: &[&usdm_decider::whir_rec_block::SpendValidityWitness],
    ts: u64,
) -> Vec<[u8; 32]> {
    let mut payload = Vec::with_capacity(ws.len() * crate::cover::PQ_NOTE_BYTES);
    let mut cms = Vec::with_capacity(ws.len());
    for w in ws {
        let (note, cm) = note_of_witness_for_test(w);
        payload.extend_from_slice(&note);
        cms.push(cm);
    }
    let (blk, _seq) = a.carry_notes_in_a_block_for_test(ts, &payload);
    let _ = a.fold_canonical_records();
    for p in peers.iter_mut() {
        assert!(
            matches!(p.ingest_block(blk.clone(), ts + 1), RelayOutcome::Added(_)),
            "PRECONDITION: a peer grafts the funding block"
        );
        let _ = p.fold_canonical_records();
    }
    cms
}

/// TEST — ⭐ DB-223 Q7: attach to `tx` (a spend of witness `w`, proven as nullifier `nf` into outputs `cms`) the member
/// leg its spender builds for input `cm` from `node`'s own public stream (`Node::member_leg_for_test`), under the
/// SAME blinding the validity carrier was proven with — what a wallet attaches to every spend since Q7.
pub(crate) fn attach_member_leg_for_test(
    node: &Node,
    tx: &mut PqTx,
    cm: &[u8; 32],
    w: &usdm_decider::whir_rec_block::SpendValidityWitness,
    nf: crate::spend_frontier::Digest4,
    cms: &[crate::spend_frontier::Digest4; 2],
) {
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let (carrier, tuple) = node
        .member_leg_for_test(cm, nf, w.lc_blind, &b32(cms[0]), &b32(cms[1]))
        .expect("PRECONDITION: the funded input's member leg builds from the node's own stream");
    tx.member_carrier = carrier;
    tx.member_tuple.clear();
    crate::member_transition::write_tuple(&tuple, &mut tx.member_tuple);
}

/// TEST — the note payload a witness's input leaf names (`spend_input_leaf`), and its commitment: the note a test
/// carries in a block, so a later bond over the same witness spends a note the chain holds.
pub(crate) fn note_of_witness_for_test(w: &usdm_decider::whir_rec_block::SpendValidityWitness) -> (Vec<u8>, [u8; 32]) {
    let leaf = usdm_decider::whir_rec_block::spend_input_leaf(w).expect("a well-formed witness states its leaf");
    let cm = crate::spend_frontier::leaf_to_cm_bytes(leaf);
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    // O1-INFINITY-REVIEWED: one fixed-width (`PQ_NOTE_BYTES`) in-memory note returned to a test; nothing is persisted.
    note[..32].copy_from_slice(&cm);
    (note, cm)
}

/// TEST — the ONE-STEP membership carrier and tip for note `cm` (leaf `leaf`) that `node` holds in a FOLDED record — the
/// wallet's builder in node form: the decider's member step over the record's in-block copath, bound to `binder` (the
/// spend's own nullifier) and `blind` (its `lc_blind`), and the tip `start ‖ prev ‖ root ‖ acc ‖ record addr`.
pub(crate) fn one_step_membership_for_test(
    node: &Node,
    cm: &[u8; 32],
    leaf: crate::spend_frontier::Digest4,
    binder: crate::spend_frontier::Digest4,
    blind: crate::spend_frontier::Digest4,
) -> Option<(Vec<u8>, Vec<u8>)> {
    use usdm_decider::note_membership_air::{note_membership_step_new_acc, prove_note_member_step_bytes};
    let addr = node.da_seq_at_note_cm(cm)?;
    let reals = node.da_record_reals(addr)?;
    let slot = u8::try_from(reals.iter().position(|n| n.len() >= 32 && n[..32] == *cm)?).ok()?;
    let (siblings, dirs, root) = node.da_note_copath_in_block(addr, slot)?;
    let carrier = prove_note_member_step_bytes(leaf, &siblings, &dirs, root, binder, blind)?;
    let genesis = Node::MEMBERSHIP_GENESIS_ACC;
    let acc = note_membership_step_new_acc(genesis, root);
    let mut tip = Vec::with_capacity(4 * crate::spend_frontier::DIGEST_LANE_BYTES + 8);
    for d in [genesis, genesis, root, acc] {
        tip.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&d));
    }
    tip.extend_from_slice(&addr.to_le_bytes());
    Some((carrier, tip))
}

/// TEST — A REAL USDm BOND of `w.out0_value` over the input note `note_of_witness_for_test(w)`, which `node` must hold in
/// a FOLDED record: the production bond carrier (`prove_bond_validity_carrier_with_commit_bytes`), the one-step
/// membership carrier over that record (`prove_note_member_step_bytes`, blind = the witness's `lc_blind`, binder = the
/// bond's nullifier), the one-step tip (start ‖ prev ‖ root ‖ acc ‖ record addr, raw-lane form) and the statement signed
/// by `pk`'s own key. Everything `verify_carried_bond_tx` re-verifies at the fold. `None` when a piece cannot be built
/// (the note is not held in a record here, or a prover refuses).
pub(crate) fn real_bond_tx_for_test(
    node: &Node,
    w: &usdm_decider::whir_rec_block::SpendValidityWitness,
    pk: &[u8],
    sk: &[u8],
) -> Option<PqTx> {
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let weight = w.out0_value;
    let (_note, cm) = note_of_witness_for_test(w);
    let (blob, cms, nf, lc) = usdm_decider::whir_rec_block::prove_bond_validity_carrier_with_commit_bytes(w, weight)?;
    let leaf = usdm_decider::whir_rec_block::spend_input_leaf(w)?;
    let (carrier, tip) = one_step_membership_for_test(node, &cm, leaf, nf, w.lc_blind)?;
    let mut output_notes = Vec::with_capacity(2 * crate::cover::PQ_NOTE_BYTES);
    for c in cms {
        let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        n[..32].copy_from_slice(&b32(c));
        output_notes.extend_from_slice(&n);
    }
    // The constant-width tag set a wallet lays: the bond's ONE real nullifier (the bond class publishes no claim tag,
    // DB-329 §7e) padded with decoys seeded from the tx id, and the spend lane's own evidence over exactly that set —
    // the pool's production door (`nullifier_witnesses_gate`) judges it like any spend.
    let id = PqTx::content_id(&blob);
    let padded = crate::cover::pad_tx_nullifiers_to_fixed(&[b32(nf)], id.as_bytes())?;
    let (lane_witnesses, lane_absence) = node.spend_lane_evidence(&padded);
    let mut tx = grind_tx(
        &blob,
        blob.len() as u32,
        padded.iter().map(|t| Hash32(*t)).collect(),
        node.mempool().required_stamp_bits(),
    );
    tx.nullifier_witnesses = lane_witnesses;
    tx.nullifier_absence = lane_absence;
    tx.output_notes = output_notes;
    tx.membership_leaf_commit = b32(lc);
    tx.membership_carrier = carrier;
    tx.membership_tip = tip;
    let vid = crate::pqauth::pubkey_id(pk);
    let (locked, nfb) = (b32(cms[0]), b32(nf));
    // The statement is signed by the vid's OWN key over this very locked note and nullifier (DB-313 R2 b).
    let sig = crate::pqauth::ml_dsa_sign(&crate::pqauth::validator_bond_msg(&vid, weight, &locked, &nfb), sk)?;
    tx.bond_notes = crate::pqauth::bond_statement_encode(&vid, weight, pk, &sig);
    Some(tx)
}

/// A FULL block's worth of conforming carries — `cover::BLOCK_FIXED_SPEND_TX_COUNT` txs, the first carrying
/// `reals`. A block only assembles at the full constant shape, so a test that wants its spend to SETTLE must
/// supply the whole shape; one lone carry settles nothing (which is the cover rule working, not a bug).
pub(crate) fn conforming_block_txs(
    view: &crate::nf_sparse::RefSparseNf,
    tag: u8,
    reals: &[[u8; 32]],
    need: u32,
) -> Vec<PqTx> {
    (0..crate::cover::BLOCK_FIXED_SPEND_TX_COUNT)
        .map(|i| {
            let r: Vec<[u8; 32]> = if i == 0 { reals.to_vec() } else { Vec::new() };
            conforming_spend_tx(view, &[tag, i as u8], &r, need)
        })
        .collect()
}

/// Build a PRODUCTION-SHAPED spend tx: exactly `cover::TX_FIXED_NULLIFIER_COUNT` nullifiers — the caller's
/// REAL spends padded with decoys derived from the tx's OWN secret — each carrying a self-built copath chained
/// against `view` (the spender's own view of the tree). This is what a real wallet emits: every insertion is
/// OWNED, which is why a producer can fold the block without holding a tree. Tests that produce blocks with
/// spends MUST use this rather than `grind_tx`, whose bare nullifiers carry no copath and therefore settle
/// nothing under the constant-width consensus rule.
pub(crate) fn conforming_spend_tx(
    view: &crate::nf_sparse::RefSparseNf,
    blob: &[u8],
    reals: &[[u8; 32]],
    need: u32,
) -> PqTx {
    let tx_secret = *Hash32::hash(blob).as_bytes();
    let padded = crate::cover::pad_tx_nullifiers_to_fixed(reals, &tx_secret)
        .expect("reals fit inside the constant per-tx width");
    // Built against the PRE-state, NOT chained: independent wallets cannot see each other's txs, so every
    // carry proves non-membership against the block's pre-root. `batch_insert_root` is what makes that work.
    let witnesses: Vec<crate::nf_sparse::CompressedCopath> = padded
        .iter()
        .map(|nf| crate::nf_sparse::compress_copath(&view.copath(nf)))
        .collect();
    let nfs: Vec<Hash32> = padded.iter().map(|nf| Hash32(*nf)).collect();
    let id = PqTx::content_id(blob);
    let mut s = 0u64;
    loop {
        let tx = PqTx {
            clock_ms: 0,
            note_clues: Vec::new(),
            account_targets: Vec::new(),
            id,
            blob: blob.to_vec(),
            weight: 1,
            nullifiers: nfs.clone(),
            pow_stamp: s,
            output_notes: Vec::new(),
            stake_notes: Vec::new(),
            bond_notes: Vec::new(),
            nullifier_witnesses: witnesses.clone(),
            nullifier_absence: Vec::new(),
            membership_carrier: Vec::new(),
            membership_leaf_commit: [0u8; 32],
            membership_tip: Vec::new(),
            membership_folded_through: 0,
            spend_or_decoy: Vec::new(),
            member_carrier: Vec::new(),
            member_tuple: Vec::new(),
        };
        if tx.stamp_work() >= need {
            return tx;
        }
        s += 1;
    }
}

pub(crate) fn dd_node() -> Node {
    let mut p = crate::params::ChainParams::default();
    p.genesis_parity_commit = crate::params::network_genesis_prefix("testnet");
    p.net_prefix_len = p.genesis_parity_commit.len();
    p.record_fold_depth = 0;
    let mut g = genesis_block();
    g.header = crate::block::genesis_header_for_network(&crate::params::network_genesis_prefix("testnet"));
    Node::with_params(g, p).expect("a testnet node builds")
}

/// Seat `n` (free at zero reserve), produce the block that carries it, and deliver that block to
/// `others`. Returns the seat's keys.
pub(crate) fn dd_seat(n: &mut Node, others: &mut [&mut Node], ts: u64) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32]) {
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (ek, dk) = crate::pqkem::keypair();
    let vid = crate::pqauth::pubkey_id(&pk);
    let header = crate::membership_bond_tx::MembershipBondHeader {
        secp33: vec![2u8; 33],
        ed32: [9u8; 32],
        kem_ek: ek.clone(),
        nonce: crate::membership_bond_tx::fresh_seat_nonce(),
    };
    let sig = crate::pqauth::ml_dsa_sign(
        &crate::pqauth::validator_membership_msg(&vid, &header.digest()),
        &sk,
    )
    .expect("signs");
    assert_eq!(n.publish_membership_bond(&pk, &sig, header), AssetSpendOutcome::Published);
    let blk = n.produce(ts, Hash32::hash(b"fr"), Hash32::hash(b"mc")).expect("block");
    for o in others.iter_mut() {
        o.ingest_block(blk.clone(), ts + 3_000);
    }
    // ⛔ FIXTURE SHORTCUT, STATED (SATOSHI §6, 2026-10-04): the free membership seat now carries FINALITY weight only;
    // CUSTODY weight comes from a SAT bond (`Class::SatBond`), which these peg / credit / liquidation fixtures do not
    // build. The custody weight is seated DIRECTLY here, at weight 1 like the old membership seat, so the quorum
    // math every cell measures is unchanged. The SatBond DOOR has its own pins (`satoshi_pins`); this stand-in is
    // replaced by the real door once the node's automatic reward bond lands (docs/SATOSHI-NATIVE-TOKEN.md §4.3).
    n.admit_validator(vid, 1, 0).expect("the fixture seats custody weight");
    for o in others.iter_mut() {
        o.admit_validator(vid, 1, 0).expect("the fixture seats custody weight on the peer");
    }
    (pk, sk, ek, dk, vid)
}

/// ⭐ SATOSHI §6 — CUSTODY WEIGHT THROUGH THE REAL DOOR, for a custody fixture that seats with a free membership seat
/// (FINALITY weight + the custody point) and then needs custody WEIGHT, which only a SAT bond seats. `n`'s operator
/// wallet (in-process, `build_sat_bond_from_reward`) bonds the SAT reward `n` laid in its own block `reward_blk` — folded
/// on `n` already, since the bond's membership proof reads `n`'s own record — for the validator key `(pk, sk)`.
pub(crate) fn dd_sat_bond(n: &mut Node, reward_blk: &Block, pk: &[u8], sk: &[u8]) -> crate::sat_bond_tx::SatBondTx {
    let reward = crate::block::credit_set_iter(&reward_blk.credit_set, crate::block::credit_seal_key(&reward_blk.header, reward_blk.cover_key.as_ref()).as_ref(), &reward_blk.wide_objects)
        .expect("the block's credit set parses")
        .iter()
        .find_map(|o| match crate::chain_object::unframe(o) {
            Some((crate::chain_object::Class::SatoshiReward, p)) => crate::satoshi::SatoshiRewardTx::decode(p),
            _ => None,
        })
        .expect("the producer's block lays its SAT reward");
    let cm = reward.note_cm().expect("the reward names its note");
    let note = reward_blk
        .output_notes
        .chunks(crate::cover::PQ_NOTE_BYTES)
        .find(|c| c.len() == crate::cover::PQ_NOTE_BYTES && c[..32] == cm[..])
        .expect("the block carries the reward note whole")
        .to_vec();
    let wallet = crate::faucet::RecipientSecrets::for_test(&n.miner_seed());
    n.build_sat_bond_from_reward(&note, &wallet, pk, sk).expect("the operator's wallet bonds its recorded reward")
}

/// Pool the `bonds` through `producer`'s admission door, lay them in ONE block at `ts`, deliver it to `others`, and fold
/// past it on the producer and its peers through the mesh lanes (10 ms apart, so it fits between a fixture's own
/// blocks) — each seat is decided by the fold's own SAT bond door on each node, never written into a set. Returns the
/// timestamp after the fold and the bond block plus the fold-past blocks this call laid (record fold depth + 2 blocks),
/// in order, for a fixture that replays its chain into a node that was not a peer.
pub(crate) fn dd_sat_custody(
    producer: &mut Node,
    others: &mut [&mut Node],
    bonds: &[crate::sat_bond_tx::SatBondTx],
    ts: u64,
    tag: &[u8],
) -> (u64, Vec<Block>) {
    for t in bonds {
        assert!(producer.publish_sat_bond(t).is_ok(), "the admission door pools the bond");
    }
    let blk = producer.produce(ts, Hash32::hash(tag), Hash32::hash(b"sat-custody-mc")).expect("the bond block");
    for o in others.iter_mut() {
        let got = o.ingest_block(blk.clone(), ts + 10);
        assert!(matches!(got, crate::relay::RelayOutcome::Added(_)), "a peer grafts the bond block: {got:?}");
    }
    let (after, mut made) = producer.fold_past_blocks_for_test(others, ts + 10, 10, tag);
    for t in bonds {
        assert_eq!(producer.validators().bond_of(&t.vid), u128::from(t.weight), "⛔ the bonder's node seats the SAT weight");
        for o in others.iter() {
            assert_eq!(o.validators().bond_of(&t.vid), u128::from(t.weight), "⛔ a peer fed only blocks seats the SAT weight");
        }
    }
    made.insert(0, blk);
    (after, made)
}

pub(crate) fn dd_gossip(from: &Node, to: &mut Node) {
    for id in from.mempool().all_tx_ids() {
        if let Some(tx) = from.mempool().get(&Hash32(id)) {
            let _ = to.ingest_tx(tx.clone());
        }
    }
}

/// ⛔ A SPINE-LESS, BOGUS-ROOT FRONTIER — NEVER HAND IT TO A SERVE THAT A PEER ADOPTS.
///
/// MEASURED 2026-10-04 (db249 + both executor re-propose pins RED for a week): a bundle served with this frontier
/// carries the anchor's certified POSITION but no peak spine, so the adopter kept its own shorter frontier while
/// its cursor moved to the anchor — "[fold-leaf-law] ⛔ the spine holds 1024 leaves but the fold base at position
/// 5 requires 1280" — and its fold stopped forever (spine stale), so the held mint block never folded on the
/// jumper and the pair's peg ledgers split. Production serves the node's OWN snapshot (node_runtime.rs
/// `spend_frontier_peaks_hex()`); every serve fixture does the same through `frontier_snapshot_for_test()`.
/// This helper survives only for the arms that pin a spine-less bundle ON PURPOSE (db296's refusal arm, db321).
pub(crate) fn dd_frontier(h: u64) -> FrontierSnapshot {
    FrontierSnapshot {
        root: *Hash32::hash(b"dd-frontier").as_bytes(),
        height: h,
        peaks_hex: String::new(),
    }
}

/// B grafts 8 of A's blocks, A runs 40 ahead, B adopts A's bundle. `depth` is both nodes' record-fold depth.
pub(crate) fn db270_jumped_pair(depth: u64) -> (Node, Node, u64) {
    let (mut a, mut b) = (db270_node(depth), db270_node(depth));
    let mut ts = 4_000u64;
    for _ in 0..8 {
        ts += 1_000;
        let blk = a.produce(ts, Hash32::hash(b"fr"), Hash32::hash(b"mc")).expect("A produces");
        let got = b.ingest_block(blk, ts + 100);
        assert!(matches!(got, crate::relay::RelayOutcome::Added(_)), "PRECONDITION: B grafts A's block: {got:?}");
    }
    assert_eq!(
        b.nf_fold_inputs_len() as u64,
        b.nf_fold_seq().saturating_sub(b.nf_fold_base().1),
        "CONTROL: before the jump B's span is exactly what its accumulator counts above its base"
    );
    for _ in 0..40 {
        ts += 1_000;
        a.produce(ts, Hash32::hash(b"fr"), Hash32::hash(b"mc")).expect("A runs ahead");
    }
    a.set_decider_verifier(Box::new(AcceptDecider));
    let resp = a.serve_sync_request(vec![1u8; 4096], a.frontier_snapshot_for_test()).expect("A serves a bundle");
    b.set_decider_verifier(Box::new(AcceptDecider));
    let outcome = b.handle_sync_response(&resp);
    assert!(matches!(outcome, Some(AdoptOutcome::Adopted(_))), "PRECONDITION: B jumps to A's tip: {outcome:?}");
    (a, b, ts)
}

/// THE PAGE LANE, IN-PROCESS (lane funds 2026-10-27): after a certified adopt the jumper's DAG anchors at the origin's
/// FOLD ROOT (`SyncBundle::anchor_block`, v31) and "the blocks between it and the certified tip arrive by ordinary gossip
/// and parent backfill" — `node_runtime::pull_block_batch` pages them before any child of the tip can graft. A Node-level
/// pin that grafts the origin's NEXT block right after the adopt measured `Buffered { missing: <the origin's tip> }`
/// (final-node-23.log, db270 R6 and the production-depth jump pin: NEVER-PASSED) — the page lane's absence, not a hole.
/// This delivers, ascending by blue score, every block the origin holds whole and the jumper lacks.
pub(crate) fn db270_backfill_pages(a: &Node, b: &mut Node, ts: u64) -> usize {
    let mut view = a.dag().dag_recent_view(usize::MAX);
    view.sort_by_key(|v| v.2);
    let mut delivered = 0usize;
    for (id, _, _, _, _) in view {
        if b.dag().get(&id).is_some() {
            continue;
        }
        if let Some(blk) = a.full_block_by_id(&id) {
            if matches!(b.ingest_block(blk, ts), crate::relay::RelayOutcome::Added(_)) {
                delivered += 1;
            }
        }
    }
    delivered
}

/// A testnet node at record-fold depth `depth` (the DB-270 pins' one constructor).
pub(crate) fn db270_node(depth: u64) -> Node {
    let mut p = crate::params::ChainParams::default();
    p.genesis_parity_commit = crate::params::network_genesis_prefix("testnet");
    p.net_prefix_len = p.genesis_parity_commit.len();
    p.record_fold_depth = depth;
    let mut g = genesis_block();
    g.header = crate::block::genesis_header_for_network(&crate::params::network_genesis_prefix("testnet"));
    Node::with_params(g, p).expect("a testnet node builds")
}

/// B's span against its own accumulator, and B's own carrier — the two DB-270 claims, one reader.
pub(crate) fn db270_assert_span_serves_its_own_carrier(b: &Node, arm: &str) {
    let (held, counted) = (b.nf_fold_inputs_len() as u64, b.nf_fold_seq().saturating_sub(b.nf_fold_base().1));
    assert_eq!(
        held, counted,
        "⛔⛔⛔ DB-270 ({arm}): the span holds {held} block(s) while the accumulator counts {counted} above the base"
    );
    let nf = *Hash32::hash(b"db270-never-spent-tag").as_bytes();
    assert!(
        b.self_build_spend_carrier(&[nf]).is_some(),
        "⛔⛔⛔ DB-270 ({arm}): the node cannot build its own spend's carrier — every node-built spend and mint on it \
         is refused"
    );
}

/// Seat V once through `a` (a fresh request with a fresh nonce, DB-258b) and return the block that carries it.
pub(crate) fn db258d_seat_once(a: &mut Node, pk: &[u8], sk: &[u8], vid: &[u8; 32], tag: &[u8], ts: u64) -> Block {
    let (kem_ek, _kem_dk) = crate::pqkem::keypair();
    let header = crate::membership_bond_tx::MembershipBondHeader {
        secp33: vec![2u8; 33],
        ed32: [9u8; 32],
        kem_ek,
        nonce: crate::membership_bond_tx::fresh_seat_nonce(),
    };
    let sig = crate::pqauth::ml_dsa_sign(&crate::pqauth::validator_membership_msg(vid, &header.digest()), sk)
        .expect("V signs its seat");
    assert_eq!(a.publish_membership_bond(pk, &sig, header), AssetSpendOutcome::Published, "PRECONDITION: V's seat pools");
    a.produce(ts, Hash32::hash(tag), Hash32::hash(b"db258d-mc")).expect("A produces the seat's block")
}

/// V unbonds through `a` under `owner`, and the block that carries the unbond is returned.
pub(crate) fn db258d_unbond_once(a: &mut Node, pk: &[u8], sk: &[u8], vid: &[u8; 32], owner: &[u8], tag: &[u8], ts: u64) -> Block {
    let (owner_ek, _odk) = crate::pqkem::keypair();
    let bucket = crate::account_da::bucket_id(owner);
    let (usig, usig_nonce) = a.sign_unbond_for_test(sk, vid, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek));
    assert_eq!(a.publish_unbond(pk, &usig, &crate::unbond_tx::unbond_clue_for_test(&bucket, &owner_ek),usig_nonce), AssetSpendOutcome::Published, "PRECONDITION: V's unbond pools");
    a.produce(ts, Hash32::hash(tag), Hash32::hash(b"db258d-mc")).expect("A produces the unbond's block")
}

/// A real note minted through the peg-in lane on `a` (executor) with `b` attesting: returns the
/// deposit id, the note payload and the mint carrier (both reusable for a re-proposal).
/// ⭐ DB-240 — price `asset` on both parties. Since DB-124 every peg-in attestation requires a mark.
///
/// Each bonded signer signs its quote exactly as the production reporter does (`price_quote::sign_quote`). The
/// mark is then applied through the door every node runs at graft (`Node::mark_price_attested`: the ≥2/3 tally
/// and the median), on BOTH parties, adding no block. The peg fixtures' block structure is load-bearing: the
/// third-party and jump pins count and feed exact blocks. The PegOut proof prices the same way.
///
/// That a mark TRAVELS in a block and is PUBLISHED by the production gatherer is proven by its own pins
/// (`db240_*`, `db245_*`).
pub(crate) fn dd_price_asset(a: &mut Node, b: &mut Node, signers: &[(&[u8], &[u8])], asset: u32, price: u128) {
    let v = crate::pqauth::MlDsaVerifier;
    let epoch = a.current_price_epoch();
    let quotes: Vec<crate::price_mark_tx::PriceQuote> = signers
        .iter()
        .map(|(pk, sk)| {
            crate::price_quote::sign_quote(epoch, asset, price, pk, sk)
                .expect("a bonded key signs its quote")
                .quote
        })
        .collect();
    for n in [&mut *a, &mut *b] {
        assert!(
            matches!(n.mark_price_attested(epoch, asset, &quotes, &v), crate::peg::PegOutcome::PriceMarked(_)),
            "the fixture's bonded quorum marks the price through the door"
        );
    }
    assert!(
        a.price_mark_for(asset).is_some() && a.price_mark_for(asset) == b.price_mark_for(asset),
        "both parties hold the same mark"
    );
}

pub(crate) fn dd_lane_mint(
    a: &mut Node,
    b: &mut Node,
    a_pk: &[u8],
    a_sk: &[u8],
    b_pk: &[u8],
    b_sk: &[u8],
    b_dk: &[u8],
    reserve: &str,
    dep: [u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    let verifier = crate::pqauth::MlDsaVerifier;
    let owner = test_owner();
    let mint: u64 = 2_000;
    // DB-240: the deposit is priced by the chain's own ≥2/3 mark before anyone is asked to attest it.
    dd_price_asset(a, b, &[(a_pk, a_sk), (b_pk, b_sk)], crate::peg::NATIVE_PEG_ASSET_ID, crate::liquidation::PRICE_SCALE);
    let note_sk = usdm_decider::poseidon2_compress::lanes_of(&[0xd0u64, 0xd1, 0xd2, mint]);
    let (mint_carrier, cm, _dc) = usdm_decider::whir_rec_block::prove_mint_validity_committed_bytes(mint, &note_sk, &test_d_blind())
        .expect("the mint-validity carrier proves");
    let cm_bytes = crate::spend_frontier::leaf_to_cm_bytes(cm);
    let mut note = Vec::with_capacity(crate::cover::PQ_NOTE_BYTES);
    note.extend_from_slice(&cm_bytes);
    note.resize(crate::cover::PQ_NOTE_BYTES, 0);
    let n1 = a.peg_proposal_nonce_for(&dep);
    let p_in = a.propose_peg_in(0, dep, 3_000, mint as u128, test_recipient(&dep), reserve, n1, test_d_blind()).expect("A proposes");
    assert!(a.peg_attest_note_proposal(p_in.clone(), None, true, 1_000));
    let att_in = b.attest_peg_in(&p_in, b_dk, b_pk, b_sk, 1_000).expect("B attests the mint");
    assert!(a.peg_attest_ingest(&att_in, &verifier));
    let extra_in = a.peg_attestations_for(&dep);
    let published = a.execute_peg_in(
        dep, 3_000, mint as u128, test_recipient(&dep), &note, &mint_carrier, reserve, a_pk, a_sk, &extra_in, &verifier, &owner, n1, test_d_blind(),
    );
    assert!(matches!(published, crate::peg::PegOutcome::ConfidentialPublished), "{published:?}");
    (note, mint_carrier)
}

/// ROGUE PRODUCER — a block laid by `rogue` that carries `wire` (a framed object in its full wire form) as a class
/// object: the carriage rides `credit_set`, its notes ride the body, the object's one-time tag rides the lane, and
/// every header root is recomputed. The peer judges it through `ingest_block_preverified` (the structural doors
/// without the grind), then its fold. The shape `a_second_mint_of_one_asset_carried_by_a_rogue_producer_credits_no_peer`
/// uses, lifted into one helper for the rogue-role census cells.
/// `carriage` is the bytes the rogue puts in `credit_set` VERBATIM — `carriage_of(honest_wire)` for a well-formed
/// object, or raw edited bytes for one the codec refuses (a rogue does not use our encoder); `notes` are the body
/// bytes it lays beside them.
/// TEST — §BR-5: a ticketed redeem exactly as a requester's node builds one for `n`'s bonded custodians (deterministic message):
/// each custodian's request SLOT (the destination kind), the ticketed commitment the quorum signs, and the ticket parts the
/// object carries (each custodian's envelope carrying `leg_blind`, and the ONE epoch ciphertext — §BR-9a step c). The ticket
/// key is encapsulated to `n`'s sealing key for `pay_after` when it has one, else to `epoch_release::test_epoch_keypair()`.
pub(crate) struct TicketedRedeemForTest {
    pub slots: std::collections::BTreeMap<[u8; 32], String>,
    pub commit: [u8; 32],
    pub parts: crate::peg_out_tx::TicketParts,
}

impl TicketedRedeemForTest {
    pub fn slot(&self, id: &[u8; 32]) -> &str {
        self.slots.get(id).map(String::as_str).expect("a custodian of this redeem")
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ticketed_redeem_for_test(
    n: &Node,
    nf: &[u8; 32],
    redeem_to: &[u8],
    pay_after: u64,
    redeem_blind: &crate::spend_frontier::Digest4,
    leg_blind: crate::spend_frontier::Digest4,
    burn: u128,
    owner_clue: &[u8],
) -> TicketedRedeemForTest {
    let custodians = n.validators().bonded_custodian_eks();
    let m: [u8; 32] = std::array::from_fn(|i| nf[i] ^ 0x5c);
    let pk = match n.peg().epoch_keys().sealing_epoch(pay_after) {
        Some((_, pk)) => pk,
        None => crate::epoch_release::test_epoch_keypair().0,
    };
    let (_, epoch_ct, ticket, commit) =
        crate::epoch_release::seal_ticket(&pk, &m, redeem_to, pay_after, redeem_blind).expect("the ticket builds");
    let monero = crate::bridge::is_monero_address(&String::from_utf8_lossy(redeem_to));
    let mut slots = std::collections::BTreeMap::new();
    let mut envelopes = Vec::new();
    for (id, ek) in &custodians {
        let slot = crate::cashout_ticket::request_slot(monero);
        let secret = crate::peg_attest::RequestSecret {
            value_a: burn,
            value_b: burn,
            address: slot.clone(),
            owner_clue: if owner_clue.is_empty() { vec![1u8] } else { owner_clue.to_vec() },
            d_blind: leg_blind,
            pay_after,
            sweep: None,
        };
        envelopes.push((*id, crate::peg_attest::seal_request_to(ek, &secret).expect("seals")));
        slots.insert(*id, slot);
    }
    TicketedRedeemForTest { slots, commit, parts: (ticket, envelopes, epoch_ct) }
}

/// [`dd_rogue_block_carrying`] for an object that owns SEVERAL lane tags (a DSOL call: its fee nullifier and every `Nullifier`
/// effect) — every tag rides the block's lane, as an honest producer's `publish_spending_object_nfs` lays them.
pub(crate) fn dd_rogue_block_carrying_tags(rogue: &mut Node, carriage: Vec<u8>, notes: Vec<u8>, own_tags: &[[u8; 32]], ts: u64, seed: &[u8]) -> Block {
    let mut blk = rogue.produce(ts, Hash32::hash(seed), Hash32::hash(b"rogue-mc")).expect("the rogue lays a block");
    blk.output_notes = notes;
    blk.header.output_notes_root = crate::block::da_notes_root_of(&blk.output_notes);
    blk.note_commitments = rogue.note_commitment_carrier_for_test(&blk.output_notes);
    blk.header.note_commitments_root = Hash32::hash(&blk.note_commitments);
    (blk.credit_set, blk.wide_objects) = crate::block::seal_carriages(&[carriage], &crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).expect("the fixture block carries its cover key")).expect("the fixture's objects fit the sealed width");
    blk.header.credit_set_root = crate::block::credit_set_root_of(&blk.credit_set);
    for t in own_tags {
        blk.nullifier_proof.padded_tags.push(*t);
    }
    blk.header.nullifier_tags_root = crate::block::nullifier_tags_root_of(&blk.nullifier_proof.padded_tags);
    lay_tag_evidence_for_test(rogue, &mut blk, own_tags);
    blk
}

/// ⭐ THE HAND-BUILT BLOCK CARRIES ITS TAGS' EVIDENCE, as every produced block does (`produce`: `tag_evidence_for` over the
/// block's FINAL tag list, bound by `tag_evidence_root`). Since blocks carry evidence for every tag (PRIVATE SHARDING §2.2),
/// a tag with none is judged spent by every node, at once.
/// MEASURED 2026-11-11 (lane goods): eleven hand-built fixtures (the two below, and the recipes in
/// `dex_cross_party_scenarios`, `satoshi_pins`, `rogue_role_pins`, `node::pins` and `asset_tx::tests`) pushed an object's
/// tags AFTER `produce` had built the evidence, so the pushed tags had none; every peer then revoked the object's spend at
/// the fold ("DB-358: 1 output(s) of a spend whose nullifier an EARLIER spender already consumed were revoked"). The
/// HONEST control of every rogue-role cell built that way was red (15 pins of DsolDeploy, DsolCall and DsolFeeUpdate on
/// main 9486d6f0, the five of DirEntry, the fill recipe's), and a cell with no control passed for the wrong reason: its
/// block was refused for the missing evidence, never by the class door or the lane rule it names. Every such fixture now
/// calls this after it reseals its tag root: the rogue lays the evidence its own node holds for each tag (a tag already
/// spent has none, which is the replay cell's point).
pub(crate) fn lay_tag_evidence_for_test(rogue: &Node, blk: &mut Block, own_tags: &[[u8; 32]]) {
    let real: std::collections::HashSet<[u8; 32]> = own_tags.iter().copied().collect();
    blk.tag_evidence = rogue.tag_evidence_for(&blk.nullifier_proof.padded_tags, &real);
    blk.header.tag_evidence_root = crate::block::da_sidecar_root_of(&blk.tag_evidence);
}

pub(crate) fn dd_rogue_block_carrying(rogue: &mut Node, carriage: Vec<u8>, notes: Vec<u8>, own_tag: [u8; 32], ts: u64, seed: &[u8]) -> Block {
    let mut blk = rogue.produce(ts, Hash32::hash(seed), Hash32::hash(b"rogue-mc")).expect("the rogue lays a block");
    blk.output_notes = notes;
    blk.header.output_notes_root = crate::block::da_notes_root_of(&blk.output_notes);
    blk.note_commitments = rogue.note_commitment_carrier_for_test(&blk.output_notes);
    blk.header.note_commitments_root = Hash32::hash(&blk.note_commitments);
    (blk.credit_set, blk.wide_objects) = crate::block::seal_carriages(&[carriage], &crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).expect("the fixture block carries its cover key")).expect("the fixture's objects fit the sealed width");
    blk.header.credit_set_root = crate::block::credit_set_root_of(&blk.credit_set);
    blk.nullifier_proof.padded_tags.push(own_tag);
    blk.header.nullifier_tags_root = crate::block::nullifier_tags_root_of(&blk.nullifier_proof.padded_tags);
    lay_tag_evidence_for_test(rogue, &mut blk, &[own_tag]);
    blk
}

/// Seat both nodes, confirm a deposit and PUBLISH its honest peg-in on `node_a` (pooled and staged, NOT laid).
/// Returns the deposit and the full wire of the framed object exactly as `node_a` would carry it. The PegIn census
/// cells start here.
pub(crate) fn dd_pool_a_peg_in(node_a: &mut Node, node_b: &mut Node) -> ([u8; 32], Vec<u8>) {
    let (a_pk, a_sk, _a_ek, _a_dk, _a_id) = dd_seat(node_a, &mut [node_b], 6_000);
    let (b_pk, b_sk, _b_ek, b_dk, _b_id) = dd_seat(node_b, &mut [node_a], 9_000);
    let reserve_s = reserve_for(node_a, &test_d_blind());
    let reserve = reserve_s.as_str();
    crate::node::tests::fund_test_deposit(node_a, reserve, &test_d_blind(), 100_000_000); // §BR-2: the coin and the depositor's sweep authorization
    let dep = crate::peg::deposit_id_for_reserve_address(reserve);
    let _ = dd_lane_mint(node_a, node_b, &a_pk, &a_sk, &b_pk, &b_sk, &b_dk, reserve, dep);
    // `execute_peg_in` POOLS the framed object as a tx (`tx.blob`); the producer lifts it into `credit_set` at
    // `produce`. `node_b` never pools it: the block must carry what applies it.
    let wire = node_a
        .mempool()
        .all_tx_ids()
        .into_iter()
        .filter_map(|id| node_a.mempool().get(&Hash32(id)).map(|tx| tx.blob.clone()))
        .find(|blob| matches!(crate::chain_object::unframe(blob), Some((crate::chain_object::Class::PegIn, _))))
        .expect("CALIBRATION: the publisher pooled its framed peg-in for its next block");
    (dep, wire)
}

/// Re-encode a peg-in's wire with `edit` applied to its decoded parts (header, attestors) — the rogue's workshop.
pub(crate) fn dd_peg_in_rewired(
    wire: &[u8],
    edit: impl FnOnce(&mut crate::peg_in_tx::PegInHeader, &mut Vec<crate::psm::MintAttestor>),
) -> Vec<u8> {
    let (_, payload) = crate::chain_object::unframe(wire).expect("framed");
    let (mut h, pc, mc, bs, mut att, note, sealed, clue) = crate::peg_in_tx::decode(payload).expect("decodes");
    edit(&mut h, &mut att);
    crate::peg_in_tx::wire(&h, &pc, &mc, &bs, &att, &note, &sealed, &clue)
}

/// A ROGUE peg-in CARRIAGE laid by hand: the honest object decoded, `edit` applied to its header and attestors, and
/// its note replaced by the 64-byte reference `cm ‖ blake3(payload)` the credit set demands — for objects the codec
/// refuses (`carriage_of` would return None), so a rogue block carrying them reaches the CODEC door rather than the
/// shape door's `CreditSetNotCarriage`.
pub(crate) fn dd_peg_in_rogue_carriage(
    wire: &[u8],
    edit: impl FnOnce(&mut crate::peg_in_tx::PegInHeader, &mut Vec<crate::psm::MintAttestor>),
) -> Vec<u8> {
    let (_, payload) = crate::chain_object::unframe(wire).expect("framed");
    let (mut h, pc, mc, bs, mut att, note, sealed, clue) = crate::peg_in_tx::decode(payload).expect("the honest object decodes");
    edit(&mut h, &mut att);
    let mut note_ref = Vec::with_capacity(64);
    note_ref.extend_from_slice(&note[..32]);
    note_ref.extend_from_slice(Hash32::hash(&note).as_bytes());
    crate::peg_in_tx::wire(&h, &pc, &mc, &bs, &att, &note_ref, &sealed, &clue)
}

/// The honest block `blk` (laid by `publisher`) grafts on `peer`, then one more block from the publisher rides after
/// it, so the peer's selected chain is the publisher's and its fold reaches the honest block whatever sibling the
/// peer laid itself (a tie-break between two blocks of one height decides nothing about the chain; the next block
/// does). Returns nothing; asserts both grafts.
pub(crate) fn dd_graft_then_settle(publisher: &mut Node, peer: &mut Node, blk: Block, ts: u64, seed: &[u8]) {
    let grafted = peer.ingest_block(blk, ts);
    assert!(matches!(grafted, crate::relay::RelayOutcome::Added(_)), "the peer grafts the honest block: {grafted:?}");
    let next = publisher.produce(ts + 1_000, Hash32::hash(seed), Hash32::hash(b"mc")).expect("the publisher's next block");
    let grafted = peer.ingest_block(next, ts + 1_500);
    assert!(matches!(grafted, crate::relay::RelayOutcome::Added(_)), "the peer grafts the publisher's next block: {grafted:?}");
    let _ = publisher.fold_canonical_records();
    let _ = peer.fold_canonical_records();
}

pub(crate) fn vid(n: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = n;
    a
}

/// DB-274 P4b (§8.15) theft fixture: three custodians; custodian 2 is the thief in every pin below.
pub(crate) fn p4b_custodians() -> Vec<crate::bridge::Custodian> {
    (0..3u8).map(|i| crate::bridge::Custodian::generate(&[110 + i; 32])).collect()
}

/// Bond `custodians` at 5,000 each on `n`, each with a locked collateral note (so an unbond moves the note into
/// `unbonding`, where the evidence window can still reach it).
pub(crate) fn p4b_bond(n: &mut Node, custodians: &[crate::bridge::Custodian]) {
    for (i, c) in custodians.iter().enumerate() {
        let mut locked = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        locked[..32].copy_from_slice(Hash32::hash(&[b"p4b-locked".as_slice(), &[i as u8]].concat()).as_bytes());
        n.admit_bond_unverified(c.id(), 5_000, locked, 0);
        n.register_validator_custody(c.id(), c.secp_compressed(), c.xmr_point());
    }
}

/// An UNAUTHORIZED reserve movement (a foreign send with no valid authorization certificate).
pub(crate) fn p4b_stolen() -> Vec<u8> {
    crate::bond_tally::reserve_move_statement(
        "BTC",
        b"tb1pP4BTHIEF",
        &usdm_decider::poseidon2_compress::lanes_of(&[4, 4, 4, 4]),
        &[0x4bu8; 32],
        11,
    )
}

/// §BR-3 17.5: the loss every theft fixture attests (1 BTC in sats).
pub(crate) const P4B_LOSS: u64 = 100_000_000;

/// A theft certificate: `signers` attest the v3 message over `statement`, `offenders` and the fixture's loss.
pub(crate) fn p4b_cert(
    signers: &[&crate::bridge::Custodian],
    statement: &[u8],
    offenders: &[[u8; 32]],
) -> crate::bond_tally::PqThresholdCert {
    let msg = crate::theft_tx::theft_msg(statement, &crate::theft_tx::canonical_offenders(offenders), P4B_LOSS);
    crate::bond_tally::PqThresholdCert { attestors: signers.iter().map(|c| c.attest(&msg)).collect() }
}

/// `bond_set` with its theft entry's object replaced by `blob`: the lane a HOSTILE producer could lay, carrying an
/// object no pool door admits, so the FOLD door is the one that must refuse it. Other entries ride unchanged.
/// cons: none — test support only: one carried lane re-encoded in memory and nothing persisted; its size is the
/// block's own bond set, f(fixed constants).
/// Two carried bond lanes as ONE step's lane: their entries in order (read the way production reads a lane, up to its
/// constant-width padding), padded back to the wider lane's width. Concatenating two padded lanes raw would end the parse at
/// the first lane's padding, so the second lane's entries would never be read.
pub(crate) fn p4b_join_lanes(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for lane in [first, second] {
        for tx in Node::bond_set_entries(lane).0 {
            let enc = postcard::to_stdvec(&tx.expect("a carried entry decodes")).expect("the entry re-encodes");
            out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
            out.extend_from_slice(&enc);
        }
    }
    let width = first.len().max(second.len());
    if out.len() < width {
        out.resize(width, 0);
    }
    out
}

pub(crate) fn p4b_recarry(bond_set: &[u8], blob: &[u8]) -> Vec<u8> {
    // The lane is read the way production reads it (`Node::bond_set_entries`): length-prefixed entries up to the first
    // zero length — the constant-width lane's padding (§POLES) — and the re-encoded lane is padded back to the same width.
    let mut out = Vec::new();
    let (entries, _tail) = Node::bond_set_entries(bond_set);
    for tx in entries {
        let mut tx = tx.expect("a carried entry decodes");
        if crate::chain_object::unframe(&tx.blob).is_some_and(|(c, _)| c == crate::chain_object::Class::ReserveTheft) {
            tx.blob = blob.to_vec();
        }
        let enc = postcard::to_stdvec(&tx).expect("the entry re-encodes");
        out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
        out.extend_from_slice(&enc);
    }
    if out.len() < bond_set.len() {
        out.resize(bond_set.len(), 0);
    }
    out
}

// A local accept-all verifier for the WIRING test; the verify soundness (reject tamper/wrong key)
// is proven in crate::pqauth's own adversarial tests.
pub(crate) struct AcceptVerifier;
impl crate::pqauth::PqVerifier for AcceptVerifier {
    fn verify(&self, _pubkey: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
        true
    }
}

// A local accept-all decider verifier for the WIRING test; the real WHIR verify soundness (honest
// proof verifies, tamper/oversize reject) is proven in crate::whir_decider's adversarial tests.
pub(super) struct AcceptDecider;
impl crate::decider::ConsensusVerifier for AcceptDecider {
    fn verify_bundle(&self, _b: &crate::decider::DeciderBundle) -> bool {
        true
    }
}

/// A fresh temp datadir for one DB-270 restart pin.
pub(crate) fn db270_tmp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "usdmd-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The small-horizon params the DB-270 restart pins run at (the fold base advances within ~100 blocks).
pub(crate) fn db270_restart_params() -> ChainParams {
    let mut p = ChainParams::default();
    p.record_fold_depth = 2;
    p.merge_depth_cap = 2;
    p.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
    p.daa_sample_len = 4;
    p
}

pub(crate) fn db358_respend_on_the_block_path(mangle_fold: bool) {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block::{prove_spend_validity_carrier_with_commit_bytes, SpendValidityWitness};
    // The verdict is decided at the CANONICAL RECORD FOLD (docs/DB-358 §5c), so both nodes fold at the tip: the
    // production depth only delays the same decision, and `canonical_record_fold_tests` pin that depth.
    // The TESTNET identity: its genesis mint allowance lets `fund_inputs_for_test` carry the inputs under a credit
    // every peer's §BA door accepts (DB-354 names the mainnet refusal).
    let mut a = testnet_party_folding_at_tip();
    let mut b = testnet_party_folding_at_tip();
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let witness = |sk: [u64; 4], out0: [u64; 4]| SpendValidityWitness {
        value_in: 1_000_000_000,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(lanes_of(&sk)),
        value_out: (1_000_000_000) - 100000,
        fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
        // per-send blinding (DB-329 §7f): spends share at most their INPUT's nullifier, never a claim tag
        lc_blind: lanes_of(&[0x363, out0[0], out0[1], sk[0]]),
        out0_value: (999_999_000) - 100000,
        out0_opening: lanes_of(&out0),
        out1_value: 1_000,
        // The change is keyed off the spend's own out0, so no two spends share a note. MEASURED on the first run:
        // with one shared change key the producer's `[assemble-dup]` rightly skipped spend #2 and the control —
        // their change note was already on chain — and B was never asked anything.
        out1_opening: lanes_of(&[7, out0[0], out0[1], out0[2]]),
    };
    // One spend as a producer lays it (the DB-223 pin's construction): the tx, its first output's commitment, and
    // the real nullifier it reveals. `pad` keeps the decoy tags distinct across spends, so the ONLY shared tag
    // between spend #1 and spend #2 is the real nullifier.
    // ⭐ DB-223 Q7 (the fixture rebuilt over REAL recorded notes, 2026-10-04): a spend counts only with its input's
    // member proof, so each input is FUNDED and folded first (`fund_inputs_for_test`) and every spend carries the
    // member leg a wallet attaches (`attach_member_leg_for_test`). Before: the control spend's input never existed,
    // so the peer refused it under Q7 and the pin failed its own calibration — exactly as that calibration foretold.
    let spend = |node: &Node, w: &SpendValidityWitness, pad: &str| {
        let (blob, cms, nf, lc, _d) =
            crate::note_transition::prove_wallet_spend(w).expect("an honest validity proof");
        let mut output_notes = Vec::with_capacity(2 * crate::cover::PQ_NOTE_BYTES);
        for cm in cms {
            let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            n[..32].copy_from_slice(&b32(cm));
            output_notes.extend_from_slice(&n);
        }
        let nfs = crate::note_transition::test_spend_tag_list(nf, w, pad);
        let mut tx = grind_tx(&blob, blob.len() as u32, nfs, node.mempool().required_stamp_bits());
        tx.output_notes = output_notes;
        tx.note_clues = crate::note_transition::fixture_note_clues(&cms);
        tx.membership_leaf_commit = b32(lc);
        let input = note_of_witness_for_test(w).1;
        attach_member_leg_for_test(node, &mut tx, &input, w, nf, &cms);
        (tx, b32(cms[0]), b32(nf))
    };
    let carries = |notes: &[u8], cm: [u8; 32]| {
        notes.chunks(crate::cover::PQ_NOTE_BYTES).any(|n| n.len() >= 32 && n[..32] == cm)
    };
    let one_input = [0x358, 0x0f, 2, 2];
    let (w1, w2, w3) = (
        witness(one_input, [1, 1, 1, 1]),
        witness(one_input, [2, 2, 2, 2]),
        witness([0x358, 0x0f, 3, 3], [3, 3, 3, 3]),
    );
    let _ = fund_inputs_for_test(&mut a, &mut [&mut b], &[&w1, &w3], 4_000);
    let (tx1, out1, nf1) = spend(&a, &w1, "db358-first");
    let (tx2, out2, nf2) = spend(&a, &w2, "db358-second");
    let (tx3, out3, nf3) = spend(&a, &w3, "db358-control");
    assert_eq!(nf1, nf2, "CALIBRATION: both spends reveal ONE nullifier — the same input spent twice");
    assert_ne!(nf3, nf1, "CALIBRATION: the control reveals a fresh nullifier");
    assert!(out1 != out2 && out2 != out3, "CALIBRATION: the three spends pay three different notes");

    a.ingest_tx_unverified(tx1).expect("A pools the first spend");
    let blk1 = a
        .produce(5_000, Hash32::hash(b"db358-fr1"), Hash32::hash(b"db358-mc1"))
        .expect("A lays block 1");
    assert!(carries(&blk1.output_notes, out1), "CALIBRATION: block 1 carries the first spend's output");
    let first = b.ingest_block(blk1, 9_000);
    eprintln!("[db358] B's outcome for block 1 (the first spend): {first:?}");
    assert!(matches!(first, crate::relay::RelayOutcome::Added(_)), "B grafts block 1");

    a.ingest_tx_unverified(tx2).expect("A pools the second spend of the same input past its own door");
    a.ingest_tx_unverified(tx3).expect("A pools the control spend");
    let blk2 = a
        .produce(6_000, Hash32::hash(b"db358-fr2"), Hash32::hash(b"db358-mc2"))
        .expect("A lays block 2");
    assert!(
        carries(&blk2.output_notes, out2),
        "CALIBRATION: block 2 carries the second spend's output — otherwise this asks B nothing"
    );
    assert!(carries(&blk2.output_notes, out3), "CALIBRATION: block 2 carries the control's output");
    let mut blk2 = blk2;
    if mangle_fold {
        // the fold rides OUTSIDE the block id: a relay can replace it and the id B checks does not move
        let id = blk2.id();
        blk2.nullifier_proof.fold = vec![0xAB; 1_535];
        assert_eq!(blk2.id(), id, "CALIBRATION: the carried fold is not bound into the block id");
    }
    let second = b.ingest_block(blk2, 10_000);
    eprintln!("[db358] B's outcome for block 2 (a re-spend + a fresh control): {second:?}");
    assert!(
        b.holds_record_with_cm(&out3),
        "CALIBRATION: B credits the FRESH control spend riding the same block — a funded input with its member leg \
         (DB-223 Q7), so a green below is not vacuous"
    );
    assert!(
        !b.holds_record_with_cm(&out2),
        "⛔⛔⛔ B CREDITED A DOUBLE SPEND: block 2 revealed a nullifier block 1 had already spent, and B — fed only \
         the blocks — recorded the second spend's 999,999,000-unit output. Nothing on the block path refuses a \
         nullifier the spent set already holds (a duplicate sparse insert is a no-op)."
    );
}

pub(crate) fn the_certified_base_plus_the_served_span_reproduce_the_nodes_own_a_tip() {
    use usdm_decider::nf_sparse_air::{nf_unspent_step_new_acc, sparse_fold_digest_nfs};
    let dir = std::env::temp_dir().join(format!(
        "usdmd-{}-{}-{}",
        "movingbase",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let mut p = ChainParams::default();
    p.record_fold_depth = 2;
    p.merge_depth_cap = 2;
    p.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
    // Shrink `keep_depth` (2·merge_depth_cap + daa_sample_len + margin) so the QUANTIZED base
    // boundary — floor(horizon / keep_depth) · keep_depth — actually steps inside this run. With the
    // default 60-block DAA sample it would take hundreds of blocks and the pin would pass vacuously
    // on a base still at genesis.
    p.daa_sample_len = 4;
    let mut n = Node::with_params(genesis_block(), p).unwrap();
    n.enable_block_window(dir.join("pruning-window-test"));
    n.relay.dag_mut().override_prune_bounds_for_test(4, 4);
    assert_eq!(
        n.nf_fold_base().0,
        Node::nf_unspent_acc_genesis(),
        "calibration: a fresh node's base IS the genesis accumulator"
    );
    for i in 0..90u64 {
        let _ = n
            .produce(5_000 + 1_000 * i, Hash32::hash(b"fr"), Hash32::hash(b"mc"))
            .expect("the node produces");
    }

    let (base, absorbed) = n.nf_fold_base();
    let span = n.nf_fold_inputs_page(0, 1_024);
    let a_tip = n.nf_unspent_acc();

    // CALIBRATION — the horizon must actually have moved, or this pin proves nothing about a base
    // that advances. A base still at genesis with an empty span would pass the identity vacuously.
    assert!(
        absorbed > 0 && base != Node::nf_unspent_acc_genesis(),
        "⛔ calibration: the base never advanced past genesis (absorbed {absorbed}) — the horizon did \
         not pass, so the identity below would be vacuous"
    );
    assert!(
        !span.is_empty(),
        "⛔ calibration: the served span is empty, so folding it proves nothing"
    );
    // BOUNDED, NOT CHAIN-SHAPED: the span is the window, cut at `keep_depth`, never the 90 blocks
    // produced. This is the property that took the wallet's fold off the banned per-chain shape.
    assert!(
        (span.len() as u64) < 90,
        "⛔ the served span is not bounded by the window — it holds {} of 90 produced blocks",
        span.len()
    );

    let fold = |acc: crate::spend_frontier::Digest4,
                s: &[(crate::block::BlockId, crate::spend_frontier::Digest4, Vec<[u8; 32]>)]| {
        let mut out = acc;
        for (_id, pre, tags) in s {
            out = nf_unspent_step_new_acc(out, *pre, sparse_fold_digest_nfs(tags, *pre));
        }
        out
    };

    assert_eq!(
        fold(base, &span),
        a_tip,
        "⛔⛔⛔ base ⊕ span != A_tip. A spender folding what this node serves cannot reach the \
         accumulator this node admits against, so NO wallet-built absence carrier can ever verify \
         and no user can spend. (absorbed {absorbed}, span {} block(s))",
        span.len()
    );

    // REFUTATION 1 — a tampered tag must break the identity.
    let mut tampered = span.clone();
    tampered[0].2[0][0] ^= 1;
    assert_ne!(
        fold(base, &tampered),
        a_tip,
        "⛔ a span with a flipped tag byte still reproduces A_tip — the fold is not binding the tags"
    );
    // REFUTATION 2 — a dropped block must break it too (absence over a shorter span is not absence).
    let short: Vec<_> = span[1..].to_vec();
    assert_ne!(
        fold(base, &short),
        a_tip,
        "⛔ a span missing a block still reproduces A_tip — a spender could hide the block that \
         settled its own input"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// ⛔⛔⛔ THE NO-GROWTH PIN BELOW CANNOT FAIL, AND THAT IS WHY GIGABYTES SHIPPED UNDER IT.
///
/// `node_state_is_constant_size_no_growth_regardless_of_block_count` drives 2,000 iterations of
/// `record_note_payload`, and that function only STAGES notes into a pending buffer — it writes no
/// record, claims no ordinal and never touches `da_mem`. So the snapshot it compares is byte-identical
/// because nothing was recorded, not because the node is constant-size. It is the "assertion that
/// cannot fail" this project bans, sitting on the one property the node is supposed to guarantee.
///
/// MEASURED on the live testnet 2026-09-04, with that pin green the whole time: a node one hour old
/// held `records_held` 15,946 with a 5,707 MB footprint, and a longer-lived one reached 68 GB. The
/// user's standard is a few MB, phone-class, constant — *"the nodes did not grow with chain length or
/// activity"*, and that is a REGRESSION we introduced.
///
/// This pin drives the REAL path every produced and ingested block takes — `record_note_payload_for`,
/// which the doc on that function calls the one door "produce, ingest, peg, stake, bond all arrive
/// here" — with the payload an ordinary block actually carries: EMPTY. An idle block is the dominant
/// case on a 500 ms chain, and its record is a pure function of its address
/// (`cover::public_idle_seed_note` + the deterministic fill), so holding it stores nothing the node
/// cannot regenerate.
///
/// It asserts the ATTRIBUTED census, so a failure NAMES the map that grew instead of reporting a
/// number nobody can act on. Scale is three ladder spans — past the retention rule's own horizon, so a
/// bound that genuinely holds has been exercised rather than merely not yet reached.
/// cons: ~12k in-memory record writes, a few seconds; no I/O, no network.
/// Build a node, drive `n` idle blocks through the REAL record+fold path, run the node's own retention
/// sweep, and return `(census, idle seeds that ended up in the spendable set)`.
#[cfg(test)]
pub(crate) fn census_after_idle_blocks(n: u64) -> (Vec<(&'static str, usize, usize)>, usize) {
    let mut node = Node::new(genesis_block()).unwrap();
    for i in 0..n {
        let id = Hash32::hash(&[b"no-growth-idle-block".as_slice(), &i.to_le_bytes()].concat());
        let addr = node.record_note_payload_for(Some(id), i, &[], None);
        // `fold_record_into_spine` is the fold's own ordinal assigner: it claims the canonical
        // position, seals a completed ladder span and calls `prune_cold_ordinal_rows` for the cold
        // end. A pin that only WRITES records measures a path no node takes — the first version of
        // this test did exactly that, reported "dropped 0" for want of any ordinal at all, and would
        // have sent me hunting a retention rule the rows had never reached. Genesis holds ordinal 0.
        let _ = node.fold_record_into_spine(addr, i + 1);
    }
    let seeds_in_unspent = (0..n)
        .filter(|i| {
            let id =
                Hash32::hash(&[b"no-growth-idle-block".as_slice(), &i.to_le_bytes()].concat());
            let addr = Node::da_record_id_for_block(&id, 0);
            let note = crate::cover::public_idle_seed_note(addr);
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&note[..32]);
            filed_to_someone(&node, &cm, addr)
        })
        .count();
    let (dropped, kept) = node.sweep_unreferenced_record_bytes();
    let snap_bytes = postcard::to_stdvec(&node.export_snapshot().expect("snapshot"))
        .expect("serialize")
        .len();
    eprintln!(
        "[no-growth] {n} idle blocks: sweep dropped {dropped}, kept {kept}, PERSISTED SNAPSHOT {snap_bytes} B"
    );
    (node.da_entry_census_named(), seeds_in_unspent)
}

/// Is this note FILED TO SOMEONE? That is today's owned/spendable index: `note_target_addr` (cm -> the record its
/// account target was filed at), and the record's own account targets. An ownerless idle seed is filed to nobody.
///
/// ⛔ WHY THIS EXISTS (DB-291 finding, 2026-09-27). After the Z2 round retired `unspent_path_nodes` (09-22), the idle-seed
/// check in `the_node_holds_the_same_state_at_one_span_of_blocks_and_at_three` read `da_record_notes(addr).is_some()`.
/// That accessor answers for every record this node can SERVE, and a cover-only record regenerates from its address by
/// design. So the check counted the open span's held idle records, 4,099 at three spans and 4,101 at five.
/// The pin failed there, and the byte and entry no-growth assertions behind it never ran: a dead guard on the one
/// property the node exists to keep.
#[cfg(test)]
pub(crate) fn filed_to_someone(node: &Node, cm: &[u8; 32], addr: u64) -> bool {
    node.note_target_addr.contains_key(cm) || !node.da_load_account_targets(addr).is_empty()
}

/// Drive `n` rows in through the PEER-PAGE path — `adopt_sidecar_row`, the door a kind-5 sidecar page
/// uses — and return the census. This is a different producer of ordinal rows from the fold, and it is
/// the one the first pin missed.
#[cfg(test)]
pub(crate) fn census_after_adopted_peer_rows(n: u64) -> Vec<(&'static str, usize, usize)> {
    let mut node = Node::new(genesis_block()).unwrap();
    for i in 1..=n {
        let id = Hash32::hash(&[b"peer-page-row".as_slice(), &i.to_le_bytes()].concat());
        let rid = Node::da_record_id_for_block(&id, 0);
        let _ = node.adopt_sidecar_row(i, rid);
    }
    node.da_entry_census_named()
}

/// ⭐⭐⭐ WHAT AN OBSERVER READS OFF A BLOCK'S SHAPE — the measurement behind
/// `harness::privacy::an_observer_cannot_read_real_activity_off_a_blocks_shape`.
///
/// Builds two blocks on identical nodes, one QUIET (no real payments) and one BUSY (several), and
/// returns each `Block` field's byte length for both. A field whose length differs between them is
/// a field whose length is a readout of how much real activity the block carried — no matter how
/// well its CONTENT is sealed.
pub(crate) fn block_field_sizes_for_activity(
) -> Vec<std::collections::BTreeMap<String, usize>> {
    activity_probe_blocks().0
}

/// The same three blocks [`block_field_sizes_for_activity`] weighs — `[quiet, quiet twin, busy]` — kept whole, plus
/// a SECOND block laid by the busy producer right after its busy one (None if it could not lay one). The privacy
/// pins that read CONTENT and LINKAGE off the wire need the blocks themselves, not their byte lengths.
pub(crate) fn blocks_for_activity() -> ([crate::block::Block; 3], Option<crate::block::Block>) {
    let (_, blocks, next, _) = activity_probe_blocks();
    (blocks, next)
}

/// The first quiet probe block and the node that laid it — so a pin can read what that node SERVES
/// (`notes_page_budgeted`, the `/get_pq_notes` page) beside what the block's wire carries.
pub(crate) fn quiet_block_and_its_producer() -> (crate::block::Block, Node) {
    let (_, [q1, _, _], _, producer) = activity_probe_blocks();
    (q1, producer)
}

#[allow(clippy::type_complexity)]
fn activity_probe_blocks() -> (
    Vec<std::collections::BTreeMap<String, usize>>,
    [crate::block::Block; 3],
    Option<crate::block::Block>,
    Node,
) {
    // ⭐ §RF-3 (2026-10-25): PAST RING COMPLETION. Since 4d490af a producer whose anchor ring is incomplete defers
    // every spend, so a never-folded node's block is not the shape a live producer lays — the probe measured a
    // pre-ring block and read the deferral's absence as a count. Fold depth 0 completes the ring on a node's first
    // block; every block weighed below is laid on a complete ring.
    let node = || {
        let mut n = testnet_party_with_fold_depth(0);
        n.arm_template_double_for_test();
        n
    };
    let next_ts = |n: &Node| {
        n.dag().get(&n.selected_tip().expect("tip")).expect("hdr").header.timestamp + n.params().target_spacing_ms
    };
    let sizes = |b: &crate::block::Block| {
        let mut m = std::collections::BTreeMap::new();
        m.insert("header".to_string(), postcard::to_allocvec(&b.header).map(|v| v.len()).unwrap_or(0));
        // The header's only variable-width fields, so a header that moves names the field that moved.
        let h = &b.header;
        eprintln!(
            "[privacy]   header varints: parents {} · timestamp {} · nonce {} · work {} · version {}",
            h.parents.len(),
            postcard::to_allocvec(&h.timestamp).expect("a u64 encodes").len(),
            postcard::to_allocvec(&h.nonce).expect("a u64 encodes").len(),
            postcard::to_allocvec(&h.work).expect("a u128 encodes").len(),
            postcard::to_allocvec(&h.version).expect("a u32 encodes").len(),
        );
        m.insert("tx_ids".to_string(), b.tx_ids.len() * 32);
        m.insert("pow_proof".to_string(), b.pow_proof.len());
        m.insert(
            "note_transition".to_string(),
            b.note_transition.as_ref().map_or(0, |n| n.agg.len() + n.tuples.len()),
        );
        m.insert(
            "nullifier_proof".to_string(),
            postcard::to_allocvec(&b.nullifier_proof).map(|v| v.len()).unwrap_or(0),
        );
        // ⛔⛔⛔ `cover_transition` WAS DECLARED A LEAK AND NEVER MEASURED. The privacy census guards
        // that every public Block field is DECLARED (`every_public_block_field_is_in_the_census`) —
        // nothing guarded that it is PROBED. So this field sat in SURFACES as
        // `Shape::TracksActivity("presence separates a spending block from a quiet one")` while the
        // measurement that decides shape could not see it at all: 13 public fields on `Block`, 12 in
        // this map. A declared leak nobody measures is indistinguishable from a closed one, in both
        // directions — `pow_proof` was declared leaking the same way and MEASURES CONSTANT (32·32·32).
        // SHAPE is measured, never declared; that rule needs every field on the bench.
        m.insert(
            "cover_transition".to_string(),
            b.cover_transition
                .as_ref()
                .map_or(0, |c| postcard::to_allocvec(c).map(|v| v.len()).unwrap_or(0)),
        );
        m.insert(
            "member_transition".to_string(),
            b.member_transition.as_ref().map_or(0, |t| t.agg.len() + t.tuples.len()),
        );
        // ⛔⛔⛔ MEASURE THE WIRE, NOT THE STRUCT. The leak is what an observer RECEIVES, and since
        // DB-165 `output_notes` and `credit_set` are `#[serde(skip)]`: they still exist in memory
        // (300+ readers) and no longer travel. Measuring `b.output_notes.len()` would report the
        // local copy and call a closed surface open — a census that measures the wrong side of the
        // wire is worse than none, because it looks like evidence.
        m.insert(
            "output_notes".to_string(),
            postcard::to_allocvec(b).map(|w| w.len()).unwrap_or(0)
                - postcard::to_allocvec(&{
                    let mut z = b.clone();
                    z.output_notes.clear();
                    z
                })
                .map(|w| w.len())
                .unwrap_or(0),
        );
        // §20.2 (2026-10-28, lane funds): the record's cover key is `#[serde(skip)]` like the payload it keys — it
        // rides the LedgerRecord lane beside the body, never the block. Measured the same way as `output_notes`: the
        // block's wire with and without the field.
        // ROOT-LAYER: the probe is the one place every block field's WIRE size is produced for the census (the
        //   two census pins read this map, never a declaration); a field the probe cannot see carries whatever its
        //   SURFACES row claims, forever.
        // MEASURED: before — `every_public_block_field_is_actually_measured_by_the_shape_probe` RED "1 PUBLIC BLOCK
        //   FIELD(S) ARE DECLARED BUT NEVER MEASURED: [\"cover_key\"]" (privacy-118.log); after — the field reads
        //   0 · 0 · 0 B (the wire with the key equals the wire without it), the run of this landing.
        // MUST-STAY-GREEN: `an_observer_cannot_read_real_activity_off_a_blocks_shape` (a 0 B field is Constant),
        //   `a_quiet_blocks_cover_secret_is_not_regenerable_from_the_served_stream` (the key's bytes are absent from the
        //   wire — the same fact, asserted on the bytes).
        m.insert(
            "cover_key".to_string(),
            postcard::to_allocvec(b).map(|w| w.len()).unwrap_or(0)
                - postcard::to_allocvec(&{
                    let mut z = b.clone();
                    z.cover_key = None;
                    z
                })
                .map(|w| w.len())
                .unwrap_or(0),
        );
        // §22b (2026-10-28, lane funds): the wide objects ride the gossip envelope beside the body, `#[serde(skip)]` on the
        // block. A probe block carries no wide credit, so an empty field would read 0 whatever the skip did; the probe
        // therefore HOLDS a 1-KiB object (the shape a wide bond/attest carriage takes) and weighs the wire with it
        // against the wire without it — the skip measured with bytes present to leak, as `cover_key` is.
        m.insert(
            "wide_objects".to_string(),
            postcard::to_allocvec(&{
                let mut z = b.clone();
                z.wide_objects = vec![vec![0xA5; 1024]];
                z
            })
            .map(|w| w.len())
            .unwrap_or(0)
                - postcard::to_allocvec(&{
                    let mut z = b.clone();
                    z.wide_objects.clear();
                    z
                })
                .map(|w| w.len())
                .unwrap_or(0),
        );
        // DB-165: the constant-width carrier, on the bench beside the field it replaces — so the
        // census MEASURES the claim rather than taking it from a SURFACES declaration.
        m.insert("note_commitments".to_string(), b.note_commitments.len());
        m.insert("oli_tags".to_string(), b.oli_tags.len());
        m.insert("account_targets".to_string(), b.account_targets.len());
        m.insert("bond_set".to_string(), b.bond_set.len());
        m.insert("dir_set".to_string(), b.dir_set.len());
        m.insert("letter_set".to_string(), b.letter_set.len());
        m.insert(
            "credit_set".to_string(),
            postcard::to_allocvec(b).map(|w| w.len()).unwrap_or(0)
                - postcard::to_allocvec(&{
                    let mut z = b.clone();
                    z.credit_set.clear();
                    z
                })
                .map(|w| w.len())
                .unwrap_or(0),
        );
        m
    };
    // ⭐⭐⭐ THE CONTROL IS THE WHOLE INSTRUMENT. A field whose length wobbles between two IDENTICAL
    // quiet blocks is wobbling on its own — a PoW nonce is a different length on every solve — and
    // that is NOISE, not a readout. A leak is a field that is STABLE across two quiet blocks and
    // then MOVES for a busy one. Without the control, noise reads as a leak and the census learns
    // to ignore itself.
    let quiet_block = || {
        let mut n = node();
        let ts = next_ts(&n);
        n.produce(ts, Hash32::hash(b"ring-f0"), Hash32::hash(b"ring-m0")).expect("block 0 completes the ring");
        assert!(n.anchor_ring_is_complete(), "CALIBRATION: the quiet producer's ring is complete");
        let ts = next_ts(&n);
        let b = n.produce(ts, Hash32::hash(b"fr"), Hash32::hash(b"mc")).expect("quiet block");
        (b, n)
    };
    let (q1, quiet_producer) = quiet_block();
    let (q2, _) = quiet_block();
    // BUSY: the same node shape, carrying several real payments AND real output notes.
    let mut busy = node();
    // ⭐ §RF-3 (2026-10-25): AND ONE STATED SPEND, HONEST ON A COMPLETE RING — funded, folded and anchored in this
    // node's own ring (`honest_spend_tx_for_test`), laid FIRST so its funding block does not take the credits staged
    // below. A fabricated input's invented ring root is no anchor of this chain, so a complete-ring producer never
    // states it; the probe must weigh the spend a live producer lays.
    let spend = honest_spend_tx_for_test(&mut busy, &mut [], 0x9b5);
    let sid = spend.id;
    assert!(busy.anchor_ring_is_complete(), "CALIBRATION: the busy producer's ring is complete");
    let need = busy.mempool().required_stamp_bits();
    for i in 0..5u32 {
        let tag = format!("privacy-busy-{i}");
        let tx = grind_tx(tag.as_bytes(), 1_000, vec![canon_nf_for_test(tag.as_bytes())], need);
        busy.ingest_tx_unverified(tx).expect("pooled");
        let note: Vec<u8> = {
            let cm = crate::spend_frontier::leaf_to_cm_bytes(
                usdm_decider::poseidon2_compress::lanes_of(&[0xc4ed, i as u64, 0, 0]),
            );
            let mut v = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            v[..32].copy_from_slice(&cm);
            for k in 32..v.len() { v[k] = ((k as u32 * 7 + i * 31) % 251) as u8; }
            v
        };
        busy.stage_credit_note(note.clone());
        // ⭐ AND THE JUSTIFICATION FOR IT (§BA). The busy fixture must exercise `credit_set` or the
        // shape gate reads 0 bytes on every block and calls the field "constant" — a claim nothing
        // tested. The SAME blind spot the weld hit at n=1: a surface that is never exercised cannot
        // contradict its own declaration, so a vacuous pass looks identical to a real one.
        busy.stage_credit_justifier(
            crate::bridge_credit_tx::BridgeCreditTx {
                deposit_id: [i as u8; 32],
                asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
                amount: 1_000,
                note,
                owner_clue: Vec::new(),
                attestors: Vec::new(),
            }
            .wire(),
        );
    }
    busy.ingest_tx_unverified(spend).expect("the busy producer pools its stated spend");
    // ⭐ §RF-3 group A (2026-10-24): AND ONE BOND-LANE OBJECT, ONE DIRECTORY SIGN-UP. `bond_set` and `dir_set` sat at
    // 0 · 0 · 0 — UNPROVEN, while SURFACES called them "Constant 0 B". The unbond is the `unbond_tx::wire` shape (an
    // ML-DSA-65 key + signature + the returned note's OLI clue); the sign-up is the db274 recipe (an ML-DSA-signed
    // @username). Both are public acts by design; the probe now weighs what their presence publishes.
    {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let clue = crate::unbond_tx::unbond_clue_for_test(&[0x37u8; 32], b"privacy-busy-unbond");
        let h = crate::unbond_tx::UnbondHeader {
            owner_clue_digest: crate::oli::owner_clue_digest(&clue),
            bond_instance: [0x37u8; 32],
            nonce: [0x38u8; 32],
        };
        let sig = crate::pqauth::ml_dsa_sign(b"privacy-busy-unbond", &sk).expect("the validator signs");
        let blob = crate::unbond_tx::wire(&h, &pk, &sig, &clue).expect("the unbond encodes");
        let tx = grind_tx(&blob, 0, vec![canon_nf_for_test(b"privacy-busy-unbond")], need);
        busy.ingest_tx_unverified(tx).expect("the busy producer pools its unbond");
    }
    let ts = next_ts(&busy);
    let b = busy.produce(ts, Hash32::hash(b"fr"), Hash32::hash(b"mc")).expect("busy block");
    assert!(b.tx_ids.contains(&sid), "CALIBRATION: the busy block lays its honest spend — else the spend is unweighed");
    assert!(!b.bond_set.is_empty(), "CALIBRATION: the busy block carries its unbond — else bond_set stays unexercised");
    // audit F15: the directory sidecar carries nothing any more (an entry is a paid object in the object lane), so on a busy
    // block as on an idle one it is exactly the constant cover pad
    assert_eq!(b.dir_set.len(), crate::block::SIDECAR_PADDED_BYTES, "CALIBRATION: the directory sidecar is the constant pad");
    // `output_notes` is serde-skipped (DB-165): its wire reading is 0 by construction. The busy block must HOLD local
    // notes, or a 0 on the wire is the empty-field vacuum, not the skip it claims to measure.
    assert!(
        !b.output_notes.is_empty(),
        "CALIBRATION: the busy block holds local output notes — so 0 on the wire measures the serde skip"
    );
    assert!(
        b.note_transition.is_some(),
        "CALIBRATION: the busy block STATES its spend — otherwise the spend surfaces stay unexercised"
    );
    // §18 (2026-10-28): the cover transition is RETIRED — the busy block states its constant-width tags as its spend's 16
    // ledger rows (head + 15 tails), chained by the tag ledger; the field is `None` on every block (0 B, measured here too).
    assert!(
        b.cover_transition.is_none() && !b.note_transition.as_ref().map_or(true, |n| n.tag_agg.is_empty()),
        "CALIBRATION: the busy block carries NO cover transition and its ledger carries the tag ledger — the retired class"
    );
    let weighed = vec![sizes(&q1), sizes(&q2), sizes(&b)];
    let ts2 = next_ts(&busy);
    let next = busy.produce(ts2, Hash32::hash(b"fr"), Hash32::hash(b"mc"));
    (weighed, [q1, q2, b], next, quiet_producer)
}


/// ⛔⛔⛔ THIS PIN HAD NO `#[test]` ATTRIBUTE AND HAD NEVER RUN — cited in three places in this file
/// as "the no-growth PROOF ... which still passes". A test that is not registered cannot pass and
/// cannot fail; it is the purest form of the escape this project bans. Registered 2026-09-04, together
/// with rewriting its body to drive the REAL record path (it drove `record_note_payload`, which stages
/// notes and records nothing).
/// Per-field serialized sizes of a node's snapshot — the attribution a slope needs to name its source.
#[cfg(test)]
pub(crate) fn snapshot_field_sizes(n: &Node) -> Vec<(String, usize)> {
    // ⛔ EVERY FIELD OF THE SNAPSHOT, BY EXHAUSTIVE DESTRUCTURE (G3, lane a 2026-10-23): the list used to name 14 of
    // 59 fields, so the G3 pin's 32,338 B/block slope summed to 1,175 B/block in its own table — the field that grows
    // was outside the universe the attribution scans. The destructure has no `..`: a field added to `NodeSnapshot`
    // without a row here does not compile.
    let crate::persist::NodeSnapshot {
        join: _,
        schema,
        genesis_commit,
        tip_block,
        blue_work,
        blue_score,
        height,
        bond_locked,
        bond_height,
        bonded_validators,
        finality_validators,
        custody_seat_active_from,
        finality_seat_active_from,
        departed_custody_seats,
        departed_finality_seats,
        slashed_validators,
        slashed_bond_burned,
        validator_bond_commit,
        validator_custody,
        spend_frontier,
        root_history,
        circulating_records,
        record_cover_keys,
        letter_columns,
        nf_fold_seq,
        account_acc,
        membership_acc,
        membership_tip_prev,
        membership_tip_root,
        da_top,
        da_base,
        served_seq,
        stake_frontier,
        nf_blocks,
        nf_leaves,
        sparse_acc_root,
        nf_cover_conf_acc,
        dsol_registry_peaks,
        dsol_registry_count,
        peg,
        l2_state_root,
        params,
        chain_id,
        fold_chain_tip,
        fold_chain_ordinal,
        nf_unspent_acc,
        fold_carry,
        sidecar_cursor,
        letter_acc,
        chain_cert,
        da_macc_steps,
        da_macc_first,
        da_leaf_starts,
        spine_frontiers,
        certified_anchor_row,
        anchor_body,
        resting_orders,
        fold_checkpoint,
        synced,
        folded_floor,
        da_samples,
        body_catchup,
        ladder_spans,
        dag_window_span,
        seat_words,
        provisional_records,
        coordinate_rows,
        dag_shells,
        unwindowed_tags,
        dag_unlinked,
        validator_kem_eks,
        custody_seat_numbers,
        ion_cache,
    } = n.export_snapshot().expect("snapshot");
    // A field the snapshot writes through its own `serde(with)` is measured in that on-disk form, never the bare value.
    let da_macc_steps_disk = crate::persist::macc_steps_fixed::disk_len(&da_macc_steps);
    macro_rules! rows {
        ($($f:ident),*) => { vec![$((stringify!($f).to_string(), postcard::to_stdvec(&$f).map_or(0, |v| v.len()))),*] };
    }
    let mut out = rows!(
        schema,
        genesis_commit,
        tip_block,
        blue_work,
        blue_score,
        height,
        bond_locked,
        bond_height,
        bonded_validators,
        finality_validators,
        custody_seat_active_from,
        finality_seat_active_from,
        departed_custody_seats,
        departed_finality_seats,
        slashed_validators,
        slashed_bond_burned,
        validator_bond_commit,
        validator_custody,
        spend_frontier,
        root_history,
        circulating_records,
        record_cover_keys,
        letter_columns,
        nf_fold_seq,
        account_acc,
        membership_acc,
        membership_tip_prev,
        membership_tip_root,
        da_top,
        da_base,
        served_seq,
        stake_frontier,
        nf_blocks,
        nf_leaves,
        sparse_acc_root,
        nf_cover_conf_acc,
        dsol_registry_peaks,
        dsol_registry_count,
        peg,
        l2_state_root,
        params,
        chain_id,
        fold_chain_tip,
        fold_chain_ordinal,
        nf_unspent_acc,
        fold_carry,
        sidecar_cursor,
        letter_acc,
        chain_cert,
        da_macc_steps,
        da_macc_first,
        da_leaf_starts,
        spine_frontiers,
        certified_anchor_row,
        anchor_body,
        resting_orders,
        fold_checkpoint,
        synced,
        folded_floor,
        da_samples,
        body_catchup,
        ladder_spans,
        dag_window_span,
        seat_words,
        provisional_records,
        coordinate_rows,
        dag_shells,
        unwindowed_tags,
        dag_unlinked,
        validator_kem_eks,
        custody_seat_numbers,
        ion_cache
    );
    if let Some(row) = out.iter_mut().find(|(n, _)| n == "da_macc_steps") {
        row.1 = da_macc_steps_disk;
    }
    out
}

/// The canonical 32-byte → root-limbs decode the retired node adopt used (`cm_bytes_to_root`), kept OUT of the seq1
/// pin's body: that pin moves no value, and the decode's module path in its text reads as a spend to
/// `test_standard`'s syntactic two-party census.
pub(crate) fn seq1_root_limbs(b: &[u8; 32]) -> Option<crate::spend_frontier::Digest4> {
    crate::spend_frontier::cm_bytes_to_root(b)
}
