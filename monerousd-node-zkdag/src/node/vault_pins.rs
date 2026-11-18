// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ SAFE AT SCALE — THE CUSTODY VAULT LIFECYCLE AT THE NODE (docs/BRIDGE-SCALE-VAULTS-SPEC-20261110.md §3d): a custodian
//! that joins a vault is handed its openings and checks them itself; a vault at half strength merges its ledgers into
//! another and every forgery of that merge is refused; a custodian may not walk out of a vault it would thin while the
//! vault's ledgers stand moved. Every pin has more than one node, and every transition is asserted on what a PEER holds.
//! The cut is turned on for each test's own thread (`custody_vaults::CUT_LIVE` says what a chain does today).
use super::tests::*;
use super::*;

/// One fixture custodian: its signing key, its sealing key, its id and its Bitcoin custody point.
struct Seat {
    pk: Vec<u8>,
    sk: Vec<u8>,
    ek: Vec<u8>,
    dk: Vec<u8>,
    id: [u8; 32],
    point: Vec<u8>,
}

fn seat(i: u8) -> Seat {
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let (ek, dk) = crate::pqkem::keypair();
    let mut secret = [0x35u8; 32];
    secret[0] = i + 1;
    let x = crate::btc_tx::xonly_pubkey(&secret).expect("a custody point"); // CLASSICAL-CRYPTO-EXEMPT: a test custodian's Bitcoin custody point (bridge endpoint)
    let mut point = vec![2u8];
    point.extend_from_slice(&x);
    Seat { id: crate::pqauth::pubkey_id(&pk), pk, sk, ek, dk, point }
}

fn testnet_node() -> Node {
    let mut p = crate::params::ChainParams::default();
    p.genesis_parity_commit = crate::params::network_genesis_prefix("testnet");
    p.net_prefix_len = p.genesis_parity_commit.len();
    let mut g = genesis_block();
    g.header = crate::block::genesis_header_for_network(&crate::params::network_genesis_prefix("testnet"));
    Node::with_params(g, p).expect("a testnet node builds").with_band_prover_for_test()
}

/// Seat `s` on node `n` as the chain's bond step would (a fixture's draw: zero randomness): its custody seat, its custody
/// point, its sealing key.
fn bond(n: &mut Node, s: &Seat) {
    n.validators.admit(s.id, 5_000, 0).expect("a fixture seat");
    n.register_validator_custody(s.id, s.point.clone(), [9u8; 32]);
    n.register_custody_kem(s.id, s.ek.clone());
}

/// `count` custodians seated in order on every node (so every node holds the same seats), and SAT marked so a vault's
/// authority is priced.
fn seat_all(nodes: &mut [&mut Node], count: u8) -> Vec<Seat> {
    crate::pouw::bound_pow::arm_on_this_thread(true);
    crate::custody_vaults::TEST_CUT_LIVE.with(|c| c.set(true));
    let seats: Vec<Seat> = (0..count).map(seat).collect();
    for n in nodes.iter_mut() {
        for s in &seats {
            bond(n, s);
        }
        // the fixture's seats, as a carrier would hand them: custodian i on seat i, so vault k is custodians 16k … 16k + 15
        // (the chain's own seating is the draw, pinned in `custody_vaults`)
        n.validators.import_custody_seats(seats.iter().enumerate().map(|(i, s)| (s.id, i as u64)).collect());
        n.peg.set_price_mark_for_test(crate::peg::SAT_PRICE_ASSET_ID, 2 * crate::liquidation::PRICE_SCALE, 1);
    }
    seats
}

fn lanes(x: &[u64; 4]) -> crate::spend_frontier::Digest4 {
    usdm_decider::poseidon2_compress::lanes_of(x)
}

/// A mint note of `mint` under blind `d_blind`: `(note payload, mint carrier, commitment bytes)`.
fn mint_note(mint: u64, d_blind: crate::spend_frontier::Digest4) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let sk = lanes(&[0xf0u64, 0xf1, 0xf2, mint]);
    let (carrier, cm, _dc) = usdm_decider::whir_rec_block::prove_mint_validity_committed_bytes(mint, &sk, &d_blind).expect("mint carrier");
    let cm_bytes = crate::spend_frontier::leaf_to_cm_bytes(cm);
    let mut payload = Vec::with_capacity(crate::cover::PQ_NOTE_BYTES);
    payload.extend_from_slice(&cm_bytes);
    payload.resize(crate::cover::PQ_NOTE_BYTES, 0);
    (payload, carrier, cm_bytes)
}

/// ONE VAULT-SIGNED DEPOSIT ON VAULT `vault`, through the real custodian doors: `a` (seated as `members[0]`) proposes and
/// executes; `b` signs as `members[1..6]`, one after the other; the block and its fold-past blocks reach every node in
/// `peers` (which must hold `b`). Returns the deposit id. `tag` separates this deposit's blind and block seeds.
#[allow(clippy::too_many_arguments)]
fn vault_deposit(a: &mut Node, b: &mut Node, others: &mut [&mut Node], members: &[&Seat], vault: u32, deposit: u128, mint: u64, at: u64, tag: u64) -> [u8; 32] {
    let lane = crate::spend_frontier::digest_to_lane_bytes;
    let d = (0u64..512).map(|i| lanes(&[0x5ca1e, tag, i, 3])).find(|d| a.deposit_vault_for(&lane(d)) == vault).expect("a blind routes to the vault");
    let reserve_s = reserve_for(a, &d);
    let reserve = reserve_s.as_str();
    fund_test_deposit(a, reserve, &d, 100_000_000);
    let dep = crate::peg::deposit_id_for_reserve_address(reserve);
    let (note, carrier, _cm) = mint_note(mint, d);
    let nonce = a.peg_proposal_nonce_for(&dep);
    let p = a.propose_peg_in(0, dep, deposit, u128::from(mint), test_recipient(&dep), reserve, nonce, d).expect("the vault's custodian proposes the deposit on its own vault's ledgers");
    assert_eq!(crate::peg::ledger_vault(p.asset_id), vault, "the proposal names the vault it lands on");
    assert!(a.peg_attest_note_proposal(p.clone(), None, true, at));
    let verifier = crate::pqauth::MlDsaVerifier;
    for m in &members[1..6] {
        b.set_custodian_identity(m.id, m.dk.clone());
        let att = b.attest_peg_in(&p, &m.dk, &m.pk, &m.sk, at).expect("a member of the vault attests its vault's deposit");
        assert!(a.peg_attest_ingest(&att, &verifier), "the member's attestation counts on the executor");
    }
    let atts = a.peg_attestations_for(&dep);
    let published = a.execute_peg_in(dep, deposit, u128::from(mint), test_recipient(&dep), &note, &carrier, reserve, &members[0].pk, &members[0].sk, &atts, &verifier, &test_owner(), nonce, d);
    assert!(matches!(published, crate::peg::PegOutcome::ConfidentialPublished), "six of the vault's members carry the deposit under its ride: {published:?}");
    let mut seed = b"vault-deposit".to_vec();
    seed.extend_from_slice(&tag.to_le_bytes());
    let blk = a.produce(at + 10_000, Hash32::hash(&seed), Hash32::hash(b"vault-mc")).expect("the block with the deposit");
    let mut peers: Vec<&mut Node> = Vec::with_capacity(others.len() + 1);
    peers.push(b);
    for n in others.iter_mut() {
        peers.push(&mut **n);
    }
    for n in peers.iter_mut() {
        n.ingest_block(blk.clone(), at + 10_400);
    }
    let _ = a.fold_past_blocks_for_test(&mut peers, at + 10_000, 50, &seed);
    for n in peers.iter() {
        assert!(n.peg().deposit_minted(&dep), "⛔ a PEER did not apply the vault-signed deposit from the block");
    }
    dep
}

fn pair(n: &Node, vault: u32, asset: u32) -> (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4) {
    n.peg().vault_pair(vault, asset).expect("the ledger answers a pair")
}

fn sign(who: &[&Seat], msg: &[u8]) -> Vec<crate::psm::MintAttestor> {
    who.iter().map(|s| crate::psm::MintAttestor { pubkey: s.pk.clone(), sig: crate::pqauth::ml_dsa_sign(msg, &s.sk).expect("the key signs") }).collect()
}

/// ⭐⭐ SAFE AT SCALE, AT THE NODE (spec §3c) — TWENTY-FIVE CUSTODIANS, TWO VAULTS (16 + 9), THE REAL CUSTODIAN DOORS.
/// (Nine, not eight: a vault takes new deposits only while it holds MORE than eight members. The counts in the lines
/// below read accordingly: the vault's legs go to its nine members, six of the nine carry a deposit under the ride, and
/// the whole set is twenty-five — eleven witnesses of vault 0 beside the vault's own six.)
/// Four nodes: A proposes and executes as a member of vault 1; B signs as five more of vault 1's members, one after the
/// other; W signs as custodians of vault 0; C holds no seat and takes everything from A's blocks.
///   (1) A DEPOSIT INSIDE THE VAULT'S AUTHORITY: its proposal names vault 1 and is sealed to vault 1's eight members
///       only; a custodian of vault 0 holds no leg and signs nothing; a member refuses commitments it does not derive;
///       six of the eight carry it under the ride; C applies it from the block and holds vault 1's ledgers moved and
///       vault 0's untouched; every member's opening advanced from its own leg.
///   (2) A DEPOSIT PAST THE VAULT'S AUTHORITY is not refused: its legs go to all twenty-four; the vault's six alone
///       are refused at the door; ten custodians of vault 0 sign as WITNESSES (own leg, own watcher, the priced cover —
///       no opening of vault 1's ledgers); sixteen of twenty-four with the vault's own six carry it; C applies it.
/// Not driven here: a cash-out at the node (the ledger's burn rule has its own pin), and real foreign wallets — the
/// Bitcoin coin is the test watcher's.
#[test]
fn safe_at_scale_twenty_five_custodians_a_vault_signs_its_deposit_and_witnesses_sign_one_past_its_authority() {
    let (mut a, mut b, mut w, mut c) = (testnet_node(), testnet_node(), testnet_node(), testnet_node());
    let seats = seat_all(&mut [&mut a, &mut b, &mut w, &mut c], 25);
    let vaults = c.custody_vaults();
    assert_eq!(vaults.iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 9], "twenty-five custodians are two vaults on every node");
    let of = |v: usize| -> Vec<&Seat> { seats.iter().filter(|s| vaults[v].contains(&s.id)).collect() };
    let (v0, v1) = (of(0), of(1));
    a.set_custodian_identity(v1[0].id, v1[0].dk.clone());
    w.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    assert_eq!((a.vault_here(), w.vault_here(), c.vault_here()), (1, 0, 0), "each custodian knows its own vault; a node with no seat reads vault 0");
    let verifier = crate::pqauth::MlDsaVerifier;
    let owner = test_owner();
    let lane = crate::spend_frontier::digest_to_lane_bytes;
    let btc = crate::peg::NATIVE_PEG_ASSET_ID;
    let mut routed = (0u64..512).map(|i| lanes(&[0x5ca1e, 9, i, 3])).filter(|d| c.deposit_vault_for(&lane(d)) == 1);
    let (d1, d2) = (routed.next().expect("a blind routes to vault 1"), routed.next().expect("a second one does"));
    assert!((0u64..64).all(|i| c.deposit_vault_for(&lane(&lanes(&[0x5ca1e, 10, i, 3]))) < 2), "a deposit is routed to a vault that exists");
    let v1_genesis = pair(&c, 1, btc);

    // ── (1) INSIDE THE VAULT'S AUTHORITY ─────────────────────────────────────────────────────────────
    let reserve1_s = reserve_for(&a, &d1);
    let reserve1 = reserve1_s.as_str();
    assert_eq!(c.vault_of_reserve_address(reserve1, &d1, Some(&test_depositor_x(&d1))), Some(1), "any node reads which vault's keys hold the deposit address");
    assert!(!w.reserve_address_is_ours(reserve1, &d1, Some(&test_depositor_x(&d1))), "⛔ a custodian of vault 0 read vault 1's deposit address as its own");
    fund_test_deposit(&mut a, reserve1, &d1, 100_000_000);
    let dep1 = crate::peg::deposit_id_for_reserve_address(reserve1);
    let (note1, carrier1, cm1) = mint_note(2_000, d1);
    let n1 = a.peg_proposal_nonce_for(&dep1);
    let p1 = a.propose_peg_in(0, dep1, 3_000, 2_000, test_recipient(&dep1), reserve1, n1, d1).expect("A proposes the deposit on its own vault's ledgers");
    assert_eq!(p1.asset_id, crate::peg::vault_ledger(1, btc), "the proposal names vault 1 (and no asset)");
    assert_eq!(p1.sealed.len(), 9, "⛔ a deposit inside the vault's authority was sealed past the vault's own nine members");
    assert!(p1.sealed.iter().all(|(id, _)| vaults[1].contains(id)), "…every leg to a member of vault 1");
    assert!(a.peg_attest_note_proposal(p1.clone(), None, true, 1_000));
    assert!(w.attest_peg_in(&p1, &v0[0].dk, &v0[0].pk, &v0[0].sk, 1_000).is_none(), "⛔ a custodian of another vault signed a deposit whose legs went to vault 1 alone");
    let mut forged = p1.clone();
    forged.new_minted_commit[0] ^= 1;
    b.set_custodian_identity(v1[1].id, v1[1].dk.clone());
    assert!(b.attest_peg_in(&forged, &v1[1].dk, &v1[1].pk, &v1[1].sk, 1_000).is_none(), "⛔ a member signed commitments it does not derive from its own opening of vault 1's ledgers");
    for m in &v1[1..6] {
        b.set_custodian_identity(m.id, m.dk.clone());
        let att = b.attest_peg_in(&p1, &m.dk, &m.pk, &m.sk, 1_000).expect("a member of vault 1 attests its vault's deposit");
        assert!(a.peg_attest_ingest(&att, &verifier), "the member's attestation counts on A");
    }
    let atts1 = a.peg_attestations_for(&dep1);
    let published = a.execute_peg_in(dep1, 3_000, 2_000, test_recipient(&dep1), &note1, &carrier1, reserve1, &v1[0].pk, &v1[0].sk, &atts1, &verifier, &owner, n1, d1);
    assert!(matches!(published, crate::peg::PegOutcome::ConfidentialPublished), "six of vault 1's eight carry the deposit under its ride: {published:?}");
    assert!(!a.peg().deposit_minted(&dep1), "the executor moved nothing at execute");
    let blk1 = a.produce(12_000, Hash32::hash(b"vault-fr1"), Hash32::hash(b"vault-mc1")).expect("the block with the deposit");
    for n in [&mut b, &mut w, &mut c] {
        n.ingest_block(blk1.clone(), 12_400);
    }
    let _ = a.fold_past_blocks_for_test(&mut [&mut b, &mut w, &mut c], 12_000, 50, b"vault-deposit-1");
    assert!(c.peg().deposit_minted(&dep1), "⛔ the PEER did not apply the vault-signed deposit from the block");
    assert_ne!(pair(&c, 1, btc), v1_genesis, "the peer holds vault 1's Bitcoin ledger moved");
    assert_eq!(pair(&c, 1, btc), pair(&a, 1, btc), "…to the pair the executor holds");
    assert!(c.peg().reserve_is_zero(), "⛔ vault 1's deposit moved vault 0's ledger on the peer");
    assert!(!c.records_containing_cm(&cm1).is_empty(), "the minted note is in the peer's unspent set");
    assert!(b.fresh_bridge_openings().is_some(), "a member's openings advanced from its own leg in the block");
    assert!(a.fresh_bridge_openings().is_some(), "…and the executor's");
    assert!(w.fresh_bridge_openings().is_some(), "a custodian of vault 0 still opens ITS vault's ledgers (nothing of vault 1 touched them)");

    // ── (2) PAST THE VAULT'S AUTHORITY: never refused, signed by the whole set with witnesses ───────────────────────
    let reserve2_s = reserve_for(&a, &d2);
    let reserve2 = reserve2_s.as_str();
    fund_test_deposit(&mut a, reserve2, &d2, 100_000_000);
    let dep2 = crate::peg::deposit_id_for_reserve_address(reserve2);
    let (note2, carrier2, _) = mint_note(30_000, d2);
    let n2 = a.peg_proposal_nonce_for(&dep2);
    let p2 = a.propose_peg_in(0, dep2, 45_000, 30_000, test_recipient(&dep2), reserve2, n2, d2).expect("A proposes the larger deposit");
    assert_eq!(p2.sealed.len(), 25, "⛔ a deposit past the vault's authority was not sealed to every custodian (the whole set must judge it)");
    assert!(a.peg_attest_note_proposal(p2.clone(), None, true, 30_000));
    for m in &v1[1..6] {
        b.set_custodian_identity(m.id, m.dk.clone());
        let att = b.attest_peg_in(&p2, &m.dk, &m.pk, &m.sk, 30_000).expect("a member attests");
        assert!(a.peg_attest_ingest(&att, &verifier));
    }
    let atts2 = a.peg_attestations_for(&dep2);
    let short = a.execute_peg_in(dep2, 45_000, 30_000, test_recipient(&dep2), &note2, &carrier2, reserve2, &v1[0].pk, &v1[0].sk, &atts2, &verifier, &owner, n2, d2);
    assert!(matches!(short, crate::peg::PegOutcome::InsufficientThreshold), "⛔ a vault's quorum alone carried a deposit past its authority: {short:?}");
    for m in &v0[0..11] {
        w.set_custodian_identity(m.id, m.dk.clone());
        let att = w.attest_peg_in(&p2, &m.dk, &m.pk, &m.sk, 30_000).expect("a custodian of vault 0 attests as a witness: own leg, own watcher, the priced cover");
        assert!(a.peg_attest_ingest(&att, &verifier), "the witness's attestation counts on A");
    }
    let atts2 = a.peg_attestations_for(&dep2);
    let whole = a.execute_peg_in(dep2, 45_000, 30_000, test_recipient(&dep2), &note2, &carrier2, reserve2, &v1[0].pk, &v1[0].sk, &atts2, &verifier, &owner, n2, d2);
    assert!(matches!(whole, crate::peg::PegOutcome::ConfidentialPublished), "⛔ a deposit past a vault's authority was REFUSED with sixteen of twenty-four signed, the vault's own six among them: {whole:?}");
    let after1 = pair(&c, 1, btc);
    let blk2 = a.produce(60_000, Hash32::hash(b"vault-fr2"), Hash32::hash(b"vault-mc2")).expect("the block with the second deposit");
    for n in [&mut b, &mut w, &mut c] {
        n.ingest_block(blk2.clone(), 60_400);
    }
    let _ = a.fold_past_blocks_for_test(&mut [&mut b, &mut w, &mut c], 60_000, 50, b"vault-deposit-2");
    assert!(c.peg().deposit_minted(&dep2), "⛔ the PEER did not apply the whole-set-signed deposit from the block");
    assert_ne!(pair(&c, 1, btc), after1, "the peer holds vault 1's Bitcoin ledger moved again");
    assert_eq!(pair(&c, 1, btc), pair(&a, 1, btc));
    assert!(c.peg().reserve_is_zero(), "⛔ vault 0's ledger moved on the peer");
    assert!(w.fresh_bridge_openings().is_some(), "the witnesses' own openings are untouched: they held no opening of vault 1 and advanced none");
}

/// ⛔⛔ SAFE AT SCALE — A CUSTODIAN THAT JOINS A VAULT IS HANDED ITS OPENINGS, AND CHECKS THEM ITSELF. Twenty-four
/// custodians are two vaults by their seats (16 + 8). Vault 1 takes a deposit, so its ledgers stand moved. A twenty-fifth
/// custodian bonds: the draw seats it in vault 1 (the one vault that holds eight and has room), and every other vault's
/// members are who they were. On its own node J it opens nothing of vault 1 (it was not there when the deposit's leg was sealed), so it ASKS
/// (signed, naming the chain state it stands on). REFUSED: an answer from a custodian of another vault; an ask by a key
/// that holds no seat in the vault; an ask whose named chain state was altered in flight. A vault mate answers, sealed
/// to the joiner's key alone. On J, REFUSED: the answer with a flipped byte; an answer SIGNED BY A REAL VAULT MATE
/// whose openings do not open J's own chain (a lying giver — J installs nothing on anyone's word). The honest answer
/// installs, and J — the second party — then attests its vault's next deposit from its own opening.
#[test]
fn safe_at_scale_a_custodian_that_joins_a_vault_is_handed_its_openings_and_checks_them_itself() {
    use crate::node::opening_share::{OpeningShare, KIND_RESERVE};
    let (mut a, mut b, mut w, mut j) = (testnet_node(), testnet_node(), testnet_node(), testnet_node());
    // twenty-five: a vault takes new deposits only while it holds MORE than eight members (`Node::deposit_vault_for`)
    let seats = seat_all(&mut [&mut a, &mut b, &mut w, &mut j], 25);
    let vaults = j.custody_vaults();
    assert_eq!(vaults.iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 9], "twenty-five custodians: seats 0–15 and 16–24");
    let of = |v: usize| -> Vec<&Seat> { seats.iter().filter(|s| vaults[v].contains(&s.id)).collect() };
    let (v0, v1) = (of(0), of(1));
    a.set_custodian_identity(v1[0].id, v1[0].dk.clone());
    w.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    let _dep = vault_deposit(&mut a, &mut b, &mut [&mut w, &mut j], &v1, 1, 3_000, 2_000, 1_000, 1);
    assert!(j.peg().vault_ledgers_moved(1) && !j.peg().vault_ledgers_moved(0), "CALIBRATION: J's chain holds vault 1's ledgers moved, vault 0's on their genesis pairs");

    // THE TWENTY-FIFTH CUSTODIAN BONDS, on every node: one vault changes
    let newc = seat(200);
    for n in [&mut a, &mut b, &mut w, &mut j] {
        bond(n, &newc);
    }
    let after = j.custody_vaults();
    assert_eq!(after.iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 10], "the draw seats it in vault 1 — the one vault that holds eight members and has room");
    assert_eq!(after[0], vaults[0], "⛔ a bond changed a vault it did not join");
    assert!(after[1].contains(&newc.id) && vaults[1].iter().all(|m| after[1].contains(m)), "vault 1 is its eight members and the newcomer");
    j.set_custodian_identity(newc.id, newc.dk.clone());
    assert_eq!(j.vault_here(), 1);
    assert!(j.fresh_bridge_openings().is_none(), "CALIBRATION: the joiner opens nothing of a vault whose ledgers moved before it joined");

    // THE ASK (the chain's one opening-recovery lane, `node::opening_share`, reading the custodian's OWN vault's pairs)
    let (btc, xmr) = (crate::peg::NATIVE_PEG_ASSET_ID, crate::peg::XMR_PEG_ASSET_ID);
    let (v1_btc, v1_xmr) = (crate::peg::vault_ledger(1, btc), crate::peg::vault_ledger(1, xmr));
    let reserve_asks = |n: &Node| -> Vec<OpeningShare> { n.opening_share_asks().into_iter().filter(|m| matches!(m, OpeningShare::Ask { kind, .. } if *kind == KIND_RESERVE)).collect() };
    let asks = reserve_asks(&j);
    let mut keys: Vec<u32> = asks.iter().filter_map(|m| if let OpeningShare::Ask { key, .. } = m { Some(*key) } else { None }).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec![v1_btc, v1_xmr], "⛔ the joiner asks for exactly its own vault's two moved ledgers — never another vault's, never an asset id of vault 0");
    assert!(reserve_asks(&a).is_empty(), "a custodian that opens its vault's ledgers asks for none");
    assert!(reserve_asks(&w).is_empty(), "⛔ a custodian of vault 0 asked for a ledger of another vault (the registry names every vault's)");
    let words_of = |m: &OpeningShare| if let OpeningShare::Ask { words, .. } = m { *words } else { [0u8; 32] };
    for ask in &asks {
        assert!(w.opening_share_answer(ask).is_none(), "⛔ a custodian of ANOTHER vault answered an ask for vault 1's opening");
    }
    // a custodian of another vault naming vault 1's (public) commitments is not handed vault 1's totals
    let prying = OpeningShare::Ask { kind: KIND_RESERVE, key: v1_btc, words: words_of(&asks[0]), from: v0[0].id };
    assert!(a.opening_share_answer(&prying).is_none(), "⛔ a custodian of another vault was handed vault 1's opening by naming its commitments");
    let stranger = seat(201);
    assert!(a.opening_share_answer(&OpeningShare::Ask { kind: KIND_RESERVE, key: v1_btc, words: words_of(&asks[0]), from: stranger.id }).is_none(), "⛔ a key holding no seat was handed a vault's opening");
    let mut other_state = words_of(&asks[0]);
    other_state[0] ^= 1;
    assert!(a.opening_share_answer(&OpeningShare::Ask { kind: KIND_RESERVE, key: v1_btc, words: other_state, from: newc.id }).is_none(), "⛔ an ask naming other commitments than the chain's was answered");

    // THE ANSWER, AND WHAT THE JOINER DOES WITH IT
    let gives: Vec<OpeningShare> = asks.iter().map(|ask| a.opening_share_answer(ask).expect("a vault mate that opens the vault's ledgers answers")).collect();
    let mut flipped = gives[0].clone();
    if let OpeningShare::Give { sealed, .. } = &mut flipped {
        let k = sealed.len() / 2;
        sealed[k] ^= 1;
    }
    assert!(!j.opening_share_take(&flipped) && j.fresh_bridge_openings().is_none(), "⛔ an answer with a flipped byte installed an opening");
    // a LYING GIVER: a well-formed envelope sealed to the joiner's real key, holding an opening that opens nothing on J's
    // chain (vault 1's GENESIS opening, which its ledger left at the deposit)
    let (gr, gm) = crate::peg::psm_genesis_blinds(v1_btc);
    let lie_body = postcard::to_stdvec(&(0u128, gr, 0u128, gm)).expect("the lie encodes");
    let lie = OpeningShare::Give { kind: KIND_RESERVE, key: v1_btc, words: words_of(&asks[0]), to: newc.id, sealed: crate::node::opening_share::seal_for_test(&newc.ek, &lie_body).expect("the lie seals") };
    assert!(!j.opening_share_take(&lie) && j.fresh_bridge_openings().is_none(), "⛔ LYING GIVER: an opening that does not open the joiner's own chain was installed");
    assert!(!w.opening_share_take(&gives[0]), "an answer addressed to another custodian installs nothing");
    for give in &gives {
        assert!(j.opening_share_take(give), "the joiner installs the honest answer");
    }
    assert!(j.fresh_bridge_openings().is_some(), "⛔ the joiner still does not open its vault's ledgers");
    assert!(reserve_asks(&j).is_empty(), "…and asks no more");

    // THE SECOND PARTY HOLDS IT: the joiner attests its vault's next deposit from the opening it was handed and checked
    let lane = crate::spend_frontier::digest_to_lane_bytes;
    let d2 = (0u64..512).map(|i| lanes(&[0x5ca1e, 2, i, 3])).find(|d| a.deposit_vault_for(&lane(d)) == 1).expect("a blind routes to vault 1");
    let reserve2_s = reserve_for(&a, &d2);
    fund_test_deposit(&mut a, reserve2_s.as_str(), &d2, 100_000_000);
    let dep2 = crate::peg::deposit_id_for_reserve_address(reserve2_s.as_str());
    let n2 = a.peg_proposal_nonce_for(&dep2);
    let p2 = a.propose_peg_in(0, dep2, 3_000, 2_000, test_recipient(&dep2), reserve2_s.as_str(), n2, d2).expect("vault 1 proposes its next deposit");
    assert_eq!(p2.sealed.len(), 10, "the next deposit's legs are sealed to vault 1's ten members, the newcomer among them");
    let att = j.attest_peg_in(&p2, &newc.dk, &newc.pk, &newc.sk, 30_000).expect("⛔ the joiner could not attest its vault's deposit from the opening it was handed");
    assert!(a.peg_attest_note_proposal(p2.clone(), None, true, 30_000) && a.peg_attest_ingest(&att, &crate::pqauth::MlDsaVerifier), "the joiner's attestation counts on the executor");
}

/// ⛔⛔ SAFE AT SCALE — A VAULT'S SWEEP FEE IS BOOKED FROM A BLOCK ON EVERY NODE, AND A FORGED COST NAMING THE SAME FOREIGN
/// TRANSACTION DOES NOT STOP IT (`Class::ReserveCost`, the census's BURN cell). Twenty-four custodians (16 + 8); vault 1
/// takes a deposit. A (a custodian of vault 1) proves a cost of 300 for foreign transaction T from its own opening.
///   • A cost for T signed by FIVE of vault 1's eight rides a block: every node refuses it at its fold, the peer's
///     reserve stands, and T's one-time id is NOT spent (a refused object spends nothing).
///   • The honest cost for the SAME T — six signatures — then rides a block: the peer C holds vault 1's reserve on the
///     stated commitment, its minted side where it was, vault 0 untouched; A, a custodian of the vault, opens the new
///     pair (its opening advanced by the fee); W, a custodian of vault 0, still opens its own.
///   • The same honest object pooled again is refused by the spent set: one booking per foreign transaction.
#[test]
fn safe_at_scale_a_forged_reserve_cost_naming_a_real_sweep_does_not_stop_its_honest_booking_on_the_peer() {
    use crate::reserve_cost_tx::{ReserveCost, ReserveCostHeader};
    let (mut a, mut b, mut w, mut c) = (testnet_node(), testnet_node(), testnet_node(), testnet_node());
    let seats = seat_all(&mut [&mut a, &mut b, &mut w, &mut c], 25);
    let vaults = c.custody_vaults();
    let of = |v: usize| -> Vec<&Seat> { seats.iter().filter(|s| vaults[v].contains(&s.id)).collect() };
    let (v0, v1) = (of(0), of(1));
    a.set_custodian_identity(v1[0].id, v1[0].dk.clone());
    w.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    let btc = crate::peg::NATIVE_PEG_ASSET_ID;
    let _dep = vault_deposit(&mut a, &mut b, &mut [&mut w, &mut c], &v1, 1, 3_000, 2_000, 1_000, 1);
    let ledger = a.ledger_here(btc);
    assert_eq!(ledger, crate::peg::vault_ledger(1, btc), "A's Bitcoin ledger is vault 1's");
    let open = a.fresh_opening_for_asset(btc).expect("A opens its vault's Bitcoin ledger after the deposit");
    let txid = [0x7eu8; 32];
    let (post_reserve, sum, bound, _after) = a.peg().prove_reserve_cost(ledger, open, 300, &txid).expect("A proves the cost from its own opening");
    let header = ReserveCostHeader { ledger, cost: 300, txid, post_reserve };
    let msg = a.peg().reserve_cost_msg(ledger, 300, &txid, &post_reserve);
    assert_eq!(msg, c.peg().reserve_cost_msg(ledger, 300, &txid, &post_reserve), "every node derives the one statement from its own chain's pair");
    let before = pair(&c, 1, btc);
    let v0_before = pair(&c, 0, btc);

    // THE FORGED COST (five of eight) rides a block and is refused at every node's fold
    let forged = ReserveCost { header, sum: sum.clone(), bound: bound.clone(), attestors: sign(&v1[..5], &msg) };
    assert!(a.publish_reserve_cost(&forged).is_ok(), "CALIBRATION: the pool takes the bytes (structure only): the door is the fold's");
    let blk = a.produce(60_000, Hash32::hash(b"cost-forged"), Hash32::hash(b"vault-mc")).expect("the block with the forged cost");
    for n in [&mut b, &mut w, &mut c] {
        n.ingest_block(blk.clone(), 60_400);
    }
    let _ = a.fold_past_blocks_for_test(&mut [&mut b, &mut w, &mut c], 60_000, 50, b"cost-forged-fold");
    assert_eq!(pair(&c, 1, btc), before, "⛔ FORGE: five of eight lowered the vault's reserve on the peer");
    assert_eq!(pair(&a, 1, btc), before, "…or on the node that carried it");

    // THE HONEST COST FOR THE SAME FOREIGN TRANSACTION then books
    let honest = ReserveCost { header, sum, bound, attestors: sign(&v1[..6], &msg) };
    assert!(a.publish_reserve_cost(&honest).is_ok(), "⛔ BURN: the forged cost spent the foreign transaction's one-time id, so its honest booking was refused at the pool");
    let blk2 = a.produce(120_000, Hash32::hash(b"cost-honest"), Hash32::hash(b"vault-mc")).expect("the block with the honest cost");
    for n in [&mut b, &mut w, &mut c] {
        n.ingest_block(blk2.clone(), 120_400);
    }
    let _ = a.fold_past_blocks_for_test(&mut [&mut b, &mut w, &mut c], 120_000, 50, b"cost-honest-fold");
    assert_eq!(pair(&c, 1, btc), (post_reserve, before.1), "⛔ the PEER does not hold the vault's reserve on the booked commitment (its minted side where it was)");
    assert_eq!(pair(&c, 1, btc), pair(&w, 1, btc), "every node holds the same pair");
    assert_eq!(pair(&c, 0, btc), v0_before, "⛔ vault 1's cost moved vault 0 on the peer");
    assert_eq!(a.fresh_opening_for_asset(btc).map(|o| o.0), Some(open.0 - 300), "⛔ a custodian of the vault does not open the new pair with the reserve less the fee");
    assert!(w.fresh_bridge_openings().is_some(), "a custodian of another vault still opens its own ledgers");
    // one booking per foreign transaction: the spent set refuses the same id again
    assert!(a.publish_reserve_cost(&honest).is_err(), "⛔ REPLAY: a second booking of one foreign transaction was pooled");
}

/// ⛔⛔ SAFE AT SCALE — A VAULT AT HALF STRENGTH MERGES ITS LEDGERS INTO ANOTHER ON EVERY NODE, EVERY FORGERY IS REFUSED,
/// AND NOBODY WALKS OUT OF IT FIRST. Twenty-four custodians are two vaults (16 + 8); vault 1 takes a deposit. Nodes: A
/// (a custodian of vault 1), B (signs as five more of vault 1), W (a custodian of vault 0, the vault that takes the
/// ledgers) and C (no seat: it takes everything from blocks).
///   • THE UNBOND RULE, on the peer: a custodian of vault 1 (eight members, ledgers moved, another vault to take them)
///     may not leave; a custodian of vault 0 (sixteen) may.
///   • THE MERGE HAND-OVER: W asks vault 1's custodians for vault 1's openings — answered only because W's vault is the
///     one the chain's own rule names — and keeps each only if it opens W's own chain's pair.
///   • W proves the merge from both openings; vault 1's quorum signs the RELEASE, vault 0's the ACCEPTANCE.
///   • On the PEER C, before the honest object: FORGE (an acceptance by ten of sixteen), STRIP (a sum proof removed),
///     SUBSTITUTE (the pairs after swapped under the honest signatures) — each refused, C's ledgers unmoved.
///   • The honest merge rides W's block: C holds vault 0 on the stated pairs and vault 1 back on its genesis pairs; W
///     opens its vault's new pairs; A opens its vault's genesis pairs again. REPLAY on C: refused.
///   • The custodian of vault 1 may now leave, on every node.
#[test]
fn safe_at_scale_a_thinned_vault_merges_its_ledgers_into_another_on_both_nodes_and_every_forgery_is_refused() {
    use crate::node::opening_share::{OpeningShare, KIND_MERGE};
    use crate::vault_merge_tx::{MergeApply, VaultMerge};
    use crate::node::objects::vault_merge_tx::apply_chain_vault_merge;let (mut a, mut b, mut w, mut c) = (testnet_node(), testnet_node(), testnet_node(), testnet_node());
    let seats = seat_all(&mut [&mut a, &mut b, &mut w, &mut c], 25);
    let vaults = c.custody_vaults();
    assert_eq!(vaults.iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 9]);
    let of = |v: usize| -> Vec<&Seat> { seats.iter().filter(|s| vaults[v].contains(&s.id)).collect() };
    let (v0, v1) = (of(0), of(1));
    a.set_custodian_identity(v1[0].id, v1[0].dk.clone());
    w.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    let verifier = crate::pqauth::MlDsaVerifier;
    let (btc, xmr) = (crate::peg::NATIVE_PEG_ASSET_ID, crate::peg::XMR_PEG_ASSET_ID);
    assert_eq!(c.vault_merge_due(), None, "CALIBRATION: no merge is due while vault 1's ledgers stand on their genesis pairs");
    let _dep = vault_deposit(&mut a, &mut b, &mut [&mut w, &mut c], &v1, 1, 3_000, 2_000, 1_000, 1);
    assert_eq!(c.vault_merge_due(), None, "CALIBRATION: a vault of nine with moved ledgers keeps them: nothing is due");
    // one of vault 1's nine is slashed on every node (the chain's own involuntary exit, which no rule holds back): the
    // vault is at half strength with its ledgers moved
    for n in [&mut a, &mut b, &mut w, &mut c] {
        assert!(n.apply_slash(v1[8].id).is_some(), "the slash takes the seat");
    }
    let v1: Vec<&Seat> = v1[..8].to_vec();
    assert_eq!(c.vault_merge_due(), Some((1, 0)), "vault 1 (eight members, ledgers moved) merges into vault 0, on any node's own chain");

    // THE UNBOND RULE, judged on the peer at the unbond's own fold step
    let leaver = v1[7];
    assert!(c.apply_unbond_release(leaver.id, test_owner(), 50, 50).is_none(), "⛔ a custodian walked out of a vault at half strength whose ledgers stand moved");
    assert!(c.validators().is_bonded_custodian(&leaver.id), "…and it is still seated on the peer");
    assert!(a.apply_unbond_release(leaver.id, test_owner(), 50, 50).is_none(), "every node judges the same unbond the same way");

    // THE MERGE HAND-OVER: W (vault 0) asks vault 1's custodians
    assert!(w.vault_merge_prove().is_none(), "CALIBRATION: without the retiring vault's openings the receiving vault proves nothing");
    let merge_asks = |n: &Node| -> Vec<OpeningShare> { n.opening_share_asks().into_iter().filter(|m| matches!(m, OpeningShare::Ask { kind, .. } if *kind == KIND_MERGE)).collect() };
    let asks = merge_asks(&w);
    assert_eq!(asks.len(), 2, "a custodian of the receiving vault asks for the retiring vault's two moved ledgers");
    assert!(merge_asks(&a).is_empty() && merge_asks(&c).is_empty(), "a custodian of the retiring vault, and a node with no seat, ask for nothing");
    for ask in &asks {
        let OpeningShare::Ask { kind, key, words, .. } = ask else { unreachable!("an ask") };
        assert_eq!(crate::peg::ledger_vault(*key), 1, "the ask names a ledger of the retiring vault");
        // a custodian that does NOT sit in the receiving vault (here a member of the retiring vault itself) is not answered
        let not_receiving = OpeningShare::Ask { kind: *kind, key: *key, words: *words, from: v1[3].id };
        assert!(a.opening_share_answer(&not_receiving).is_none(), "⛔ a merge opening went to a custodian outside the vault the chain names as receiving");
        assert!(w.opening_share_answer(ask).is_none(), "a custodian of the receiving vault does not hold the retiring vault's opening to give");
        let give = a.opening_share_answer(ask).expect("a custodian of the retiring vault answers the vault that takes its ledgers");
        assert!(!c.opening_share_take(&give), "a node the answer is not addressed to keeps nothing");
        assert!(w.opening_share_take(&give), "W keeps vault 1's opening: it opens W's own chain's pair for vault 1's ledger");
    }
    assert!(merge_asks(&w).is_empty(), "…and asks no more");
    assert!(w.fresh_bridge_openings().is_some(), "keeping another vault's opening did not disturb W's own");

    // THE MERGE, proven on W from both openings; each vault signs the statement its own nodes derive
    let proven = w.vault_merge_prove().expect("W opens both vaults' ledgers and proves the sums");
    assert_eq!((proven.header.from, proven.header.into), (1, 0));
    assert_eq!(proven.legs.iter().map(|l| l.asset).collect::<Vec<_>>(), vec![btc, xmr], "one leg per ledger kind vault 1 moved: both bridge ledgers; this chain keeps no coin ledger");
    assert!(!proven.ride.is_empty(), "after the merge vault 0 stands inside its authority, so its bound rides");
    assert!(proven.release.is_empty() && proven.accept.is_empty(), "the prover signs nothing: each vault's own signers do");
    assert_eq!(a.peg().vault_merge_release_msg(1, 0), c.peg().vault_merge_release_msg(1, 0), "the release is chain facts: every node derives the same bytes");
    let release = sign(&v1[..6], &a.peg().vault_merge_release_msg(1, 0));
    let accept = sign(&v0[..11], &w.peg().vault_merge_msg(1, 0, &proven.legs));
    let posts = (proven.legs[0].post, proven.legs[1].post);
    let honest = VaultMerge { release: release.clone(), accept: accept.clone(), ..proven };
    let before = (pair(&c, 0, btc), pair(&c, 0, xmr), pair(&c, 1, btc), pair(&c, 1, xmr));
    let held = |n: &Node| (pair(n, 0, btc), pair(n, 0, xmr), pair(n, 1, btc), pair(n, 1, xmr));

    // ON THE PEER, before the honest object
    let forged = VaultMerge { accept: sign(&v0[..10], &w.peg().vault_merge_msg(1, 0, &honest.legs)), ..honest.clone() };
    assert!(matches!(apply_chain_vault_merge(&mut c, &forged.wire(), &verifier), MergeApply::Refused(crate::peg::PegOutcome::InsufficientThreshold)), "⛔ FORGE: ten of sixteen accepted another vault's ledgers on the peer");
    let mut stripped = honest.clone();
    stripped.legs[0].minted_sum.clear();
    assert!(matches!(apply_chain_vault_merge(&mut c, &stripped.wire(), &verifier), MergeApply::NotMerge), "⛔ STRIP: a merge with a sum proof removed was read as an object");
    let mut hollow = honest.clone();
    hollow.legs[0].minted_sum = hollow.legs[0].reserve_sum.clone();
    assert!(matches!(apply_chain_vault_merge(&mut c, &hollow.wire(), &verifier), MergeApply::Refused(crate::peg::PegOutcome::BadRequest)), "⛔ STRIP: the minted sum's proof replaced by the reserve's was taken");
    // a leg dropped under signatures over that shorter statement: vault 1 would keep a moved ledger and its custodians
    // could then walk away from it
    // (no bound proof, so the bound is not what refuses it: the whole set releases, as it may for any merge)
    let mut short = honest.clone();
    short.legs.truncate(1);
    short.ride.clear();
    short.release = sign(&v1.iter().chain(v0.iter()).copied().collect::<Vec<_>>(), &a.peg().vault_merge_release_msg(1, 0));
    short.accept = sign(&v0[..11], &w.peg().vault_merge_msg(1, 0, &short.legs));
    let whole_set = VaultMerge { ride: Vec::new(), release: short.release.clone(), ..honest.clone() };
    assert!(matches!(c.peg().check_vault_merge(1, 0, &whole_set.legs, &whole_set.ride, c.validators(), &verifier, &whole_set.release, &whole_set.accept), crate::peg::PegOutcome::ConfidentialPublished), "CALIBRATION: with every leg, the same whole-set release carries the merge on the peer");
    assert!(matches!(apply_chain_vault_merge(&mut c, &short.wire(), &verifier), MergeApply::Refused(crate::peg::PegOutcome::BadRequest)), "⛔ STRIP: a merge that left one of the retiring vault's moved ledgers behind was taken");
    let mut swapped = honest.clone();
    swapped.legs[0].post = posts.1;
    swapped.legs[1].post = posts.0;
    assert!(matches!(apply_chain_vault_merge(&mut c, &swapped.wire(), &verifier), MergeApply::Refused(_)), "⛔ SUBSTITUTE: pairs the receiving vault never signed were taken");
    assert_eq!(held(&c), before, "⛔ a refused merge moved the peer's ledgers");
    assert!(c.peg().vault_ledgers_moved(1), "…vault 1's ledgers still stand moved on the peer");

    // THE HONEST MERGE RIDES W'S BLOCK
    let bits = w.mempool().required_stamp_bits();
    assert!(w.ingest_tx(honest.as_pq_tx(bits)).is_ok(), "W pools the merge");
    let blk = w.produce(60_000, Hash32::hash(b"vault-merge"), Hash32::hash(b"vault-mc")).expect("W lays the merge in its block");
    for n in [&mut a, &mut b, &mut c] {
        n.ingest_block(blk.clone(), 60_400);
    }
    let _ = w.fold_past_blocks_for_test(&mut [&mut a, &mut b, &mut c], 60_000, 50, b"vault-merge-fold");
    assert_eq!((pair(&c, 0, btc), pair(&c, 0, xmr)), posts, "⛔ the PEER does not hold vault 0 on the merged pairs");
    assert!(!c.peg().vault_ledgers_moved(1), "⛔ the PEER still holds vault 1's ledgers moved");
    assert_eq!(held(&c), held(&a), "every node holds the same pairs");
    assert_eq!(held(&c), held(&w));
    assert_eq!(c.vault_merge_due(), None, "nothing is left to merge");
    assert!(w.fresh_bridge_openings().is_some(), "⛔ a custodian of the receiving vault does not open the pairs it now stands behind");
    assert!(a.fresh_bridge_openings().is_some(), "⛔ a custodian of the retiring vault does not open its vault's genesis pairs again");
    // REPLAY on the peer
    let after = held(&c);
    assert!(matches!(apply_chain_vault_merge(&mut c, &honest.wire(), &verifier), MergeApply::Refused(crate::peg::PegOutcome::Replay)), "⛔ REPLAY: the settled merge was taken again on the peer");
    assert_eq!(held(&c), after);

    // NOW THE CUSTODIAN MAY LEAVE, on every node
    for n in [&mut a, &mut w, &mut c] {
        assert!(n.apply_unbond_release(leaver.id, test_owner(), 50, 50).is_some(), "⛔ a custodian of a vault that holds nothing was kept from leaving");
    }
    assert_eq!(c.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 7], "its seat is free; vault 0 is who it was");
}

/// ⭐⭐ SAFE AT SCALE, stage three (spec §3f R7, R8) — A DUE MERGE IS DONE BY THE LANE: BOTH VAULTS SIGN WHAT THEIR OWN
/// NODES DERIVE, THE RECEIVING VAULT ONLY ONCE IT SEES THE COINS, AND THE OBJECT IS FRAMED FROM THE GATHERED LISTS.
/// Twenty-five custodians, two vaults (16 + 9); vault 1 takes a deposit of 3,000 and loses a member to a slash, so its
/// merge into vault 0 is due on every node's own chain. Nodes: A (a custodian of vault 1), B (signs as five more of
/// vault 1), W (signs as custodians of vault 0, and frames), C (no seat: it gathers and takes the object from a block).
///   • THE RELEASE is chain facts: each custodian of vault 1 signs it from its own chain, with no reading of coins.
///   • COINS FIRST: a custodian of vault 0 that holds both vaults' openings signs NO acceptance while its own Bitcoin
///     source shows less than the merged ledgers will count (2,999 of 3,000) — and signs it at 3,000. A custodian
///     with no Monero wallet still signs: the merged Monero ledgers count nothing.
///   • What does NOT count: an acceptance by a custodian of the retiring vault, a release by a key the chain does not
///     seat, a signature lifted onto other pairs.
///   • Ten of sixteen acceptances do not frame; an acceptance over OTHER pairs gathers apart and completes nothing; the
///     eleventh honest one does. W proves the sums from its own openings (what the runtime does on a worker thread),
///     the door takes the object with the lane's two lists, and it rides W's block.
///   • On the PEER: vault 0 stands on the pairs the acceptances named, vault 1 is back on its genesis pairs, and
///     nothing is due any more — the lane signs nothing for a merge that is done.
/// TWO-PARTY-REVIEWED: the signers are on A, B and W, the framer is W, and every result is asserted on C, which holds
/// no seat and only gathered signatures and folded W's block.
#[test]
fn safe_at_scale_a_due_merge_is_signed_by_both_vaults_coins_first_and_framed_from_the_lane_on_the_peer() {
    use crate::node::opening_share::{OpeningShare, KIND_MERGE};
    use crate::vault_merge_tx::VaultMergeSig;
    let (mut a, mut b, mut w, mut c) = (testnet_node(), testnet_node(), testnet_node(), testnet_node());
    let seats = seat_all(&mut [&mut a, &mut b, &mut w, &mut c], 25);
    let vaults = c.custody_vaults();
    let of = |v: usize| -> Vec<&Seat> { seats.iter().filter(|s| vaults[v].contains(&s.id)).collect() };
    let (v0, v1) = (of(0), of(1));
    a.set_custodian_identity(v1[0].id, v1[0].dk.clone());
    w.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    let verifier = crate::pqauth::MlDsaVerifier;
    let (btc, xmr) = (crate::peg::NATIVE_PEG_ASSET_ID, crate::peg::XMR_PEG_ASSET_ID);
    let _dep = vault_deposit(&mut a, &mut b, &mut [&mut w, &mut c], &v1, 1, 3_000, 2_000, 1_000, 1);
    for n in [&mut a, &mut b, &mut w, &mut c] {
        assert!(n.apply_slash(v1[8].id).is_some(), "the slash takes the seat");
    }
    let v1: Vec<&Seat> = v1[..8].to_vec();
    assert_eq!(c.vault_merge_due(), Some((1, 0)), "PRECONDITION: vault 1's merge into vault 0 is due on the peer's own chain");
    // the hand-over (pinned in the merge pin above): W keeps vault 1's openings
    for ask in w.opening_share_asks().into_iter().filter(|m| matches!(m, OpeningShare::Ask { kind, .. } if *kind == KIND_MERGE)) {
        let give = a.opening_share_answer(&ask).expect("a custodian of the retiring vault answers the vault that takes its ledgers");
        assert!(w.opening_share_take(&give));
    }
    let (header, posts, need_btc, need_xmr) = w.vault_merge_posts().expect("W derives the acceptance from its two openings");
    assert_eq!((header.from, header.into), (1, 0));
    assert_eq!((need_btc, need_xmr), (Some(3_000), Some(0)), "the merged ledgers will count vault 1's 3,000 sats, and no Monero");
    let wire = |s: &VaultMergeSig| VaultMergeSig::decode(&s.wire()).expect("a lane signature decodes");
    let before = (pair(&c, 0, btc), pair(&c, 0, xmr));

    // THE RELEASE: every custodian of the retiring vault, from its own chain
    let mut release: Vec<VaultMergeSig> = a.own_vault_merge_sigs(&v1[0].pk, &v1[0].sk, None, None);
    assert!(release.len() == 1 && release[0].posts.is_none(), "a custodian of the retiring vault signs the release and no acceptance");
    for m in &v1[1..6] {
        b.set_custodian_identity(m.id, m.dk.clone());
        release.extend(b.own_vault_merge_sigs(&m.pk, &m.sk, None, None));
    }
    assert_eq!(release.len(), 6);
    for s in &release {
        assert!(w.vault_merge_sig_ingest(&wire(s), &verifier) && c.vault_merge_sig_ingest(&wire(s), &verifier), "a release is gathered on the framer and on a node with no seat");
        assert!(!w.vault_merge_sig_ingest(&wire(s), &verifier), "a repeat is not new");
    }

    // COINS FIRST: no acceptance while this custodian's own Bitcoin source shows less than the merged ledgers count
    let accepts = |n: &Node, s: &Seat, btc_seen: Option<u128>| -> Vec<VaultMergeSig> { n.own_vault_merge_sigs(&s.pk, &s.sk, btc_seen, None).into_iter().filter(|x| x.posts.is_some()).collect() };
    assert!(accepts(&w, v0[0], None).is_empty(), "⛔ COINS FIRST: an acceptance was signed with no reading of this custodian's own Bitcoin source");
    assert!(accepts(&w, v0[0], Some(2_999)).is_empty(), "⛔ COINS FIRST: the receiving vault accepted ledgers whose coins its own source does not show (2,999 of 3,000)");
    let first = accepts(&w, v0[0], Some(3_000));
    assert!(first.len() == 1 && first[0].posts.as_deref() == Some(posts.as_slice()), "with the coins in sight it signs the pairs its own openings derive (no Monero wallet needed: no Monero is counted)");

    // what does NOT count
    let stranger = seat(99);
    let rogue = VaultMergeSig { header, posts: None, pubkey: stranger.pk.clone(), sig: crate::pqauth::ml_dsa_sign(&c.peg().vault_merge_release_msg(1, 0), &stranger.sk).expect("signs") };
    assert!(!c.vault_merge_sig_ingest(&rogue, &verifier), "⛔ a release by a key the chain does not seat was gathered");
    let outside = VaultMergeSig { header, posts: Some(posts.clone()), pubkey: v1[0].pk.clone(), sig: crate::pqauth::ml_dsa_sign(&c.peg().vault_merge_accept_msg(1, 0, &posts), &v1[0].sk).expect("signs") };
    assert!(!c.vault_merge_sig_ingest(&outside, &verifier), "⛔ an acceptance by a custodian of the RETIRING vault was gathered");
    // the two pairs swapped under their kinds: other pairs than any honest custodian derives
    let other_posts = vec![(posts[0].0, posts[1].1), (posts[1].0, posts[0].1)];
    let lifted = VaultMergeSig { posts: Some(other_posts.clone()), ..first[0].clone() };
    assert!(!c.vault_merge_sig_ingest(&lifted, &verifier), "⛔ a signature was counted for pairs it does not sign");

    // ten of sixteen do not frame; an acceptance over other pairs gathers apart; the eleventh honest one frames
    let mut accept = first;
    for m in &v0[1..11] {
        w.set_custodian_identity(m.id, m.dk.clone());
        accept.extend(accepts(&w, m, Some(3_000)));
    }
    assert_eq!(accept.len(), 11);
    for s in &accept[..10] {
        assert!(w.vault_merge_sig_ingest(&wire(s), &verifier) && c.vault_merge_sig_ingest(&wire(s), &verifier));
    }
    assert!(w.vault_merge_ready_to_frame(&verifier).is_none(), "⛔ ten of sixteen accepted another vault's ledgers");
    let lying = VaultMergeSig { header, posts: Some(other_posts.clone()), pubkey: v0[11].pk.clone(), sig: crate::pqauth::ml_dsa_sign(&w.peg().vault_merge_accept_msg(1, 0, &other_posts), &v0[11].sk).expect("signs") };
    assert!(w.vault_merge_sig_ingest(&lying, &verifier), "CALIBRATION: a seated custodian's own statement is gathered — under its own pairs");
    assert!(w.vault_merge_ready_to_frame(&verifier).is_none(), "⛔ an acceptance over other pairs completed the honest one");
    assert!(w.vault_merge_sig_ingest(&wire(&accept[10]), &verifier));
    let (release_list, accept_list, inputs) = w.vault_merge_ready_to_frame(&verifier).expect("two thirds of each vault: the framer holds both lists for the pairs its own openings derive");
    assert_eq!((release_list.len(), accept_list.len()), (6, 11));
    let mut merge = inputs.prove().expect("the framer's openings prove the sums");
    assert_eq!(merge.legs.iter().map(|l| (l.asset, l.post)).collect::<Vec<_>>(), posts, "the proven pairs are the pairs the acceptances named");
    (merge.release, merge.accept) = (release_list, accept_list);
    assert!(matches!(c.peg().check_vault_merge(1, 0, &merge.legs, &merge.ride, c.validators(), &verifier, &merge.release, &merge.accept), crate::peg::PegOutcome::ConfidentialPublished), "⛔ the door on the peer does not take the object the lane assembled");
    assert!(w.publish_vault_merge(&merge).is_ok());
    let blk = w.produce(60_000, Hash32::hash(b"merge-lane"), Hash32::hash(b"vault-mc")).expect("W lays the merge in its block");
    for n in [&mut a, &mut b, &mut c] {
        n.ingest_block(blk.clone(), 60_400);
    }
    let _ = w.fold_past_blocks_for_test(&mut [&mut a, &mut b, &mut c], 60_000, 50, b"merge-lane-fold");

    // ON THE PEER
    assert_ne!((pair(&c, 0, btc), pair(&c, 0, xmr)), before, "the receiving vault's pairs moved");
    assert_eq!(vec![(btc, pair(&c, 0, btc)), (xmr, pair(&c, 0, xmr))], posts, "⛔ the PEER does not hold vault 0 on the pairs the acceptances named");
    assert!(!c.peg().vault_ledgers_moved(1), "⛔ the PEER still holds vault 1's ledgers moved");
    for (n, name) in [(&mut a, "A"), (&mut w, "W"), (&mut c, "the peer")] {
        assert_eq!(n.vault_merge_due(), None, "{name}: nothing is due any more");
        assert!(n.vault_merge_ready_to_frame(&verifier).is_none() && n.own_vault_merge_sigs(&v0[0].pk, &v0[0].sk, Some(3_000), None).is_empty(), "{name}: the lane holds and signs nothing for a merge that is done");
    }
}

/// ⭐ SAFE AT SCALE — THE LAST CUSTODIAN OF A VAULT WHOSE LEDGERS MOVED DOES NOT LEAVE (`Node::custody_exit_held`).
/// FOUND by the lifecycle model (`models/custody-lifecycle`, invariant I6) before any node build: with no other vault
/// to merge into, the first rule let every custodian of a funded vault walk out, the last one included, and nobody
/// was left to sign a cash-out or to hand a newcomer the openings. Seven custodians, one vault, a real deposit through
/// the custodian doors; A is one custodian, B signs as five more, C holds no seat, Z is the CONTROL (the same seats,
/// no deposit). Run with the cut on and with it off (the chain as it is today): the rule is the same rule.
///   • CONTROL, on Z: with the ledgers on their genesis pairs all seven leave, the last one too.
///   • After the deposit, on the peer C: six leave one by one (the vault keeps a custodian each time); the seventh —
///     the last — is refused, on every node, and stays seated.
///   • Another custodian bonds: the seventh now leaves, on every node. The newcomer is then the last, and is refused.
#[test]
fn safe_at_scale_the_last_custodian_of_a_vault_whose_ledgers_moved_stays_until_another_bonds() {
    for cut in [true, false] {
        let (mut a, mut b, mut c, mut z) = (testnet_node(), testnet_node(), testnet_node(), testnet_node());
        let seats = seat_all(&mut [&mut a, &mut b, &mut c, &mut z], 7);
        crate::custody_vaults::TEST_CUT_LIVE.with(|l| l.set(cut));
        let all: Vec<&Seat> = seats.iter().collect();
        assert_eq!(c.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>(), vec![7], "one vault of seven (cut {cut})");
        a.set_custodian_identity(all[0].id, all[0].dk.clone());

        // CONTROL: nothing was ever deposited, so nothing holds anyone — the last custodian included
        for s in &all {
            assert!(z.apply_unbond_release(s.id, test_owner(), 50, 50).is_some(), "CALIBRATION (cut {cut}): a custodian of a vault that stands behind nothing was kept from leaving");
        }
        assert!(z.custody_vaults().iter().all(Vec::is_empty), "the control's custody set is empty");

        let _dep = vault_deposit(&mut a, &mut b, &mut [&mut c], &all, 0, 3_000, 2_000, 1_000, if cut { 7 } else { 8 });
        assert!(c.peg().vault_ledgers_moved(0), "the deposit moved the vault's ledgers on the peer");

        // six leave: each time the vault keeps a custodian, and there is no other vault to wait for
        for s in &all[1..] {
            for n in [&mut a, &mut b, &mut c] {
                assert!(n.apply_unbond_release(s.id, test_owner(), 50, 50).is_some(), "⛔ (cut {cut}) a custodian was kept from leaving a vault that keeps a custodian and has no vault to merge into");
            }
        }
        assert_eq!(c.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>(), vec![1]);

        // THE RULE, judged on the peer at the unbond's own fold step, and the same on every node
        let last = all[0];
        for n in [&mut c, &mut a, &mut b] {
            assert!(n.apply_unbond_release(last.id, test_owner(), 50, 50).is_none(), "⛔ (cut {cut}) the LAST custodian walked away from a vault whose ledgers stand moved");
            assert!(n.validators().is_bonded_custodian(&last.id), "…and it is still seated");
        }

        // another custodian bonds: the vault has a second member, so the first may go — and the newcomer is now the last
        let fresh = seat(40);
        for n in [&mut a, &mut b, &mut c] {
            bond(n, &fresh);
        }
        assert_eq!(c.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>(), vec![2], "the newcomer sits in the same vault (cut {cut})");
        for n in [&mut c, &mut a, &mut b] {
            assert!(n.apply_unbond_release(last.id, test_owner(), 50, 50).is_some(), "⛔ (cut {cut}) with another custodian seated the first was still held");
            assert!(n.apply_unbond_release(fresh.id, test_owner(), 50, 50).is_none(), "⛔ (cut {cut}) the newcomer, now the last custodian of the moved ledgers, walked away");
        }
    }
}

/// ⭐⭐ SAFE AT SCALE, stage three — NO KEY OUTLIVES ITS BOND (spec §3f R4, the release gate; `Class::VaultKey`). A
/// custodian that leaves gets its collateral back only once no alive custody key HOLDS it
/// (`PegLedger::vault_key_holds`). Two nodes on the real path: A publishes and produces, B is fed A's blocks alone;
/// every claim is read on B. Two custodians, V (who leaves) and W (who stays), each with a locked bond note; the chain
/// as it is today (one vault: the whole custody set).
///   • CALIBRATION (a pair with NO key record): V unbonds and its note returns on the peer when its window closes.
///   • ON THE PEER, before the honest object — FORGE: a take signed by W alone (half the weight). SUBSTITUTE: a take
///     naming V alone, signed by both over that statement. Each refused, the record unmoved.
///   • V and W take the key of their set (A's block): B holds it. V unbonds; its window closes; its note does NOT
///     return on B — the vault's current key names it.
///   • ARM ONE, a vault that stands behind nothing: W takes the key of {W}; the old key is replaced; once its address
///     window has passed, V's note returns on B with no retire (there is provably nothing under that key).
///   • ARM TWO, a vault whose ledgers moved: the same, and after the window V's note STILL does not return — coins may
///     sit under the old key. FORGE on the peer: a retire signed by V (no longer seated: no weight). W retires the old
///     key (A's block): V's note returns on B at the next step, byte for byte the note it locked. REPLAY: the retire
///     again is refused on the peer.
#[test]
fn safe_at_scale_a_leavers_collateral_returns_only_when_no_alive_key_names_it_on_every_node() {
    use crate::vault_key_tx::{KeyApply, VaultKey, VaultKeyHeader};
    use crate::node::objects::vault_key_tx::apply_chain_vault_key;struct Who {
        pk: Vec<u8>,
        sk: Vec<u8>,
        vid: [u8; 32],
        locked: Vec<u8>,
    }
    let who = |tag: &[u8]| -> Who {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let mut locked = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        locked[..32].copy_from_slice(Hash32::hash(tag).as_bytes());
        Who { vid: crate::pqauth::pubkey_id(&pk), pk, sk, locked }
    };
    // a pair of nodes with a short unbonding window (the merge/fold horizon: its length is not the subject), both
    // custodians bonded on both with their locked notes
    let pair = |v: &Who, w: &Who| -> (Node, Node) {
        let (mut a, mut b) = (dd_node(), dd_node());
        for n in [&mut a, &mut b] {
            let mut gp = n.params().clone();
            gp.governance_set_stake_lock_blocks(0);
            gp.merge_depth_cap = 4;
            gp.governance_set_unbonding_blocks(0);
            n.set_params(gp);
            n.admit_bond_unverified(v.vid, 50_000, v.locked.clone(), 0);
            n.admit_bond_unverified(w.vid, 50_000, w.locked.clone(), 0);
        }
        (a, b)
    };
    let cm_of = |note: &[u8]| -> [u8; 32] { note[..32].try_into().expect("a 32-byte front") };
    let sign = |signers: &[&Who], msg: &[u8]| -> Vec<crate::psm::MintAttestor> {
        signers.iter().map(|s| crate::psm::MintAttestor { pubkey: s.pk.clone(), sig: crate::pqauth::ml_dsa_sign(msg, &s.sk).expect("the key signs") }).collect()
    };
    let set = |members: &[&Who]| -> Vec<[u8; 32]> {
        let mut ids: Vec<[u8; 32]> = members.iter().map(|m| m.vid).collect();
        ids.sort_unstable();
        ids
    };
    let take = |n: &Node, members: &[&Who], signers: &[&Who], addr: &[u8]| -> VaultKey {
        let ids = set(members);
        VaultKey { attestors: sign(signers, &n.peg().vault_key_take_msg(0, &n.vault_btc_key(0), &ids, addr)), header: VaultKeyHeader::Take { vault: 0, members: ids, xmr_address: addr.to_vec() } }
    };
    // THE KEY LANE between the two nodes: A acts as custodian V, B as custodian W. Each signs, on its own node, what
    // its own chain and sources say the vault owes; every signature crosses the wire encoding and is gathered by BOTH
    // nodes against their own chains; the answer is what A — any node — can frame.
    let lane = |a: &mut Node, b: &mut Node, v: &Who, w: &Who| -> Option<VaultKey> {
        let mut sigs = a.own_vault_key_sigs(&v.pk, &v.sk, false, None);
        sigs.extend(b.own_vault_key_sigs(&w.pk, &w.sk, false, None));
        for s in &sigs {
            let s = crate::vault_key_tx::VaultKeySig::decode(&s.wire()).expect("a key signature crosses the lane");
            let (new_a, new_b) = (a.vault_key_sig_ingest(&s, &crate::pqauth::MlDsaVerifier), b.vault_key_sig_ingest(&s, &crate::pqauth::MlDsaVerifier));
            assert!(new_a && new_b, "each node gathers a custodian's signature over the statement its own chain forms");
            assert!(!b.vault_key_sig_ingest(&s, &crate::pqauth::MlDsaVerifier), "a signature gathered once is not new again (it is not relayed twice)");
        }
        a.vault_key_ready_to_frame(&crate::pqauth::MlDsaVerifier)
    };
    let (owner_ek, _dk) = crate::pqkem::keypair();
    let clue = crate::unbond_tx::unbond_clue_for_test(&crate::account_da::bucket_id(b"vault-key-gate-owner"), &owner_ek);
    let verifier = crate::pqauth::MlDsaVerifier;
    // one block of A's carrying whatever A pooled, grafted by B, then folded on both
    let carry = |a: &mut Node, b: &mut Node, ts: u64, tag: &[u8]| -> u64 {
        let blk = a.produce(ts, Hash32::hash(tag), Hash32::hash(b"vault-key-gate-mc")).expect("A produces");
        let _ = b.ingest_block(blk, ts + 400);
        a.fold_past_for_test(&mut [b], ts + 400, tag)
    };
    let unbond = |a: &mut Node, b: &mut Node, v: &Who, ts: u64, tag: &[u8]| -> u64 {
        let (sig, nonce) = a.sign_unbond_for_test(&v.sk, &v.vid, &clue);
        assert_eq!(a.publish_unbond(&v.pk, &sig, &clue, nonce), AssetSpendOutcome::Published, "V's unbond is published");
        let ts = carry(a, b, ts, tag);
        assert!(a.validators().bond_of(&v.vid) == 0 && b.validators().bond_of(&v.vid) == 0, "V's weight left at the unbond's fold, on both nodes");
        assert!(b.unbonding_due(&v.vid).is_some(), "V's collateral waits out its window on the peer");
        ts
    };

    // CALIBRATION: no key record — the chain as it is today
    let (v, w) = (who(b"gate-calib-v"), who(b"gate-calib-w"));
    let (mut a, mut b) = pair(&v, &w);
    let ts = unbond(&mut a, &mut b, &v, 5_000, b"gate-calib-u");
    let _ = a.fold_past_unbond_window_for_test(&mut [&mut b], ts, b"gate-calib-w");
    assert!(b.holds_record_with_cm(&cm_of(&v.locked)) && b.unbonding_due(&v.vid).is_none(), "CALIBRATION: with no key record, the leaver's note returns on the peer at its window");

    for moved in [false, true] {
        let (v, w) = (who(if moved { b"gate-moved-v" } else { b"gate-still-v" }), who(if moved { b"gate-moved-w" } else { b"gate-still-w" }));
        let (mut a, mut b) = pair(&v, &w);
        if moved {
            // the vault's native ledger stands MOVED on both nodes (the test seam: a deposit's effect on the pair, without
            // driving a deposit through custodians this fixture's two-key set cannot quorum)
            for n in [&mut a, &mut b] {
                let paid = n.peg.stake_paid_commit();
                n.peg.set_custody_commits_for_test(lanes(&[0x6a7e, 1, 0, 0]), lanes(&[0x6a7e, 2, 0, 0]), paid);
            }
        }
        assert_eq!(b.peg().vault_ledgers_moved(0), moved, "PRECONDITION: the vault's ledgers on the peer");

        // ON THE PEER, before the honest object
        let forged = take(&b, &[&v, &w], &[&w], b"4-vw");
        assert!(matches!(apply_chain_vault_key(&mut b, &forged.wire(), Some(1), &verifier), KeyApply::Refused(crate::peg::PegOutcome::InsufficientThreshold)), "⛔ FORGE: half the vault's weight took a key for it on the peer");
        let alone = take(&b, &[&v], &[&v, &w], b"4-v");
        assert!(matches!(apply_chain_vault_key(&mut b, &alone.wire(), Some(1), &verifier), KeyApply::Refused(crate::peg::PegOutcome::BadRequest)), "⛔ SUBSTITUTE: a key that leaves a seated custodian out was taken on the peer");
        assert!(b.peg().vault_keys(0).is_empty(), "a refused statement moved nothing on the peer");

        // THE VAULT TAKES THE KEY OF ITS SET — THROUGH THE KEY LANE, carried by A's block. One signature is half the
        // vault: nothing frames. Both: A frames the statement both chains derived.
        a.set_custodian_identity(v.vid, Vec::new());
        b.set_custodian_identity(w.vid, Vec::new());
        let alone = a.own_vault_key_sigs(&v.pk, &v.sk, false, None);
        assert_eq!(alone.len(), 1, "a custodian of a vault with no key signs its take, alone, from its own chain");
        assert!(a.own_vault_key_sigs(&w.pk, &w.sk, false, None).is_empty(), "⛔ a node signed a key statement with a key that is not its own custody identity");
        assert!(a.vault_key_sig_ingest(&alone[0], &verifier) && a.vault_key_ready_to_frame(&verifier).is_none(), "CALIBRATION: half the vault's weight frames nothing");
        let outsider = who(b"gate-outsider");
        let forged_sig = crate::vault_key_tx::VaultKeySig { header: alone[0].header.clone(), pubkey: outsider.pk.clone(), sig: crate::pqauth::ml_dsa_sign(&a.peg().vault_key_take_msg(0, &a.vault_btc_key(0), &set(&[&v, &w]), b""), &outsider.sk).expect("signs") };
        assert!(!b.vault_key_sig_ingest(&forged_sig, &verifier), "⛔ the lane gathered a signature from a key the chain seats in no vault");
        let mut other_statement = alone[0].clone();
        other_statement.header = VaultKeyHeader::Take { vault: 0, members: set(&[&v]), xmr_address: Vec::new() };
        assert!(!b.vault_key_sig_ingest(&other_statement, &verifier), "⛔ the lane gathered a statement this node's own chain does not derive");
        a.vault_key_book.clear();
        let honest = lane(&mut a, &mut b, &v, &w).expect("both custodians' signatures frame the take on a node that gathered them");
        assert_eq!(honest.header, VaultKeyHeader::Take { vault: 0, members: set(&[&v, &w]), xmr_address: Vec::new() }, "the framed statement is the one both chains derive: the seats, and no Monero address (neither runs a wallet)");
        assert_eq!(honest.attestors.len(), 2);
        assert!(a.publish_vault_key(&honest).is_ok(), "A pools the take");
        let ts = carry(&mut a, &mut b, 5_000, b"gate-take");
        assert_eq!(b.peg().vault_key_current(0).map(|k| k.members.clone()), Some(set(&[&v, &w])), "⛔ the PEER does not hold the vault's key from the block");
        assert_eq!(b.peg().vault_keys(0), a.peg().vault_keys(0), "both nodes hold the same record");

        // V LEAVES; its window closes; the gate holds its note on the peer
        let ts = unbond(&mut a, &mut b, &v, ts + 1_000, b"gate-unbond");
        let ts = a.fold_past_unbond_window_for_test(&mut [&mut b], ts, b"gate-window");
        for (n, name) in [(&a, "A"), (&b, "the peer")] {
            assert!(!n.holds_record_with_cm(&cm_of(&v.locked)) && n.unbonding_due(&v.vid).is_some(), "⛔ (moved {moved}) {name} returned a leaver's collateral while the vault's current key names it");
        }

        // W TAKES THE KEY OF {W}, through the lane: the key names a custodian no longer seated, so the take is due at
        // once; V's node signs nothing (it holds no seat); the old key is replaced, still alive
        assert!(a.own_vault_key_sigs(&v.pk, &v.sk, false, None).is_empty(), "⛔ a custodian that left signed a key statement");
        assert_eq!(b.vault_key_take_due(false, None), Some(VaultKeyHeader::Take { vault: 0, members: set(&[&w]), xmr_address: Vec::new() }), "the remaining custodian's chain says its vault owes a key that no longer names the leaver");
        let next = lane(&mut a, &mut b, &v, &w).expect("the one seated custodian's signature is the whole vault");
        assert!(a.publish_vault_key(&next).is_ok());
        let ts = carry(&mut a, &mut b, ts + 1_000, b"gate-take-2");
        let rows = b.peg().vault_keys(0).to_vec();
        assert_eq!(rows.iter().map(|k| (k.members.len(), k.replaced_tick.is_some())).collect::<Vec<_>>(), vec![(2, true), (1, false)], "the peer holds the old key replaced and the new one current");
        // a few more folded blocks: the replaced key's address window (one twenty-first of this fixture's window) passes
        let ts = carry(&mut a, &mut b, ts + 1_000, b"gate-after-window");
        if !moved {
            // ARM ONE: the vault stands behind nothing and the old key can no longer be paid — nothing holds V
            for (n, name) in [(&a, "A"), (&b, "the peer")] {
                assert!(n.holds_record_with_cm(&cm_of(&v.locked)) && n.unbonding_due(&v.vid).is_none(), "⛔ {name} still holds a leaver's collateral for a key that can no longer be paid, in a vault that stands behind nothing");
            }
            continue;
        }
        // ARM TWO: the vault's ledgers moved — coins may sit under the old key, so V is held until the vault retires it
        for (n, name) in [(&a, "A"), (&b, "the peer")] {
            assert!(!n.holds_record_with_cm(&cm_of(&v.locked)) && n.unbonding_due(&v.vid).is_some(), "⛔ {name} returned a leaver's collateral while a key it holds may still hold the vault's coins");
        }
        let old = rows[0].since_tick;
        let by_leaver = VaultKey { header: VaultKeyHeader::Retire { vault: 0, since_tick: old }, attestors: sign(&[&v], &b.peg().vault_key_retire_msg(0, old)) };
        assert!(matches!(apply_chain_vault_key(&mut b, &by_leaver.wire(), Some(u64::MAX / 2), &verifier), KeyApply::Refused(crate::peg::PegOutcome::InsufficientThreshold)), "⛔ FORGE: the leaver retired the key that holds its own collateral, on the peer");
        // THE RETIRE, through the lane — signed only on what W's OWN sources show: nothing before they report; nothing
        // while its Bitcoin book holds a coin under the old key's leaf; the retire once they show it empty
        assert!(b.vault_key_retire_due().is_none() && lane(&mut a, &mut b, &v, &w).is_none(), "⛔ a custodian whose sources have not reported signed a retire");
        b.set_vault_key_coin_view([rows[0].btc.leaf].into_iter().collect());
        assert!(b.vault_key_retire_due().is_none(), "⛔ a custodian signed the retire of a key its own book still shows a coin under");
        b.set_vault_key_coin_view(std::collections::BTreeSet::new());
        assert_eq!(b.vault_key_retire_due(), Some(VaultKeyHeader::Retire { vault: 0, since_tick: old }), "its sources show the old key empty and its window has passed: the retire is due");
        let retire = lane(&mut a, &mut b, &v, &w).expect("the vault's one member's signature frames the retire");
        assert_eq!(retire.header, VaultKeyHeader::Retire { vault: 0, since_tick: old });
        assert!(a.publish_vault_key(&retire).is_ok(), "A pools the retire");
        let ts = carry(&mut a, &mut b, ts + 1_000, b"gate-retire");
        assert_eq!(b.peg().vault_keys(0).len(), 1, "⛔ the PEER still holds the retired key");
        let _ = carry(&mut a, &mut b, ts + 1_000, b"gate-release");
        for (n, name) in [(&a, "A"), (&b, "the peer")] {
            assert!(n.holds_record_with_cm(&cm_of(&v.locked)) && n.unbonding_due(&v.vid).is_none(), "⛔ {name} did not return the leaver's collateral once no alive key held it");
        }
        assert!(matches!(apply_chain_vault_key(&mut b, &retire.wire(), Some(u64::MAX / 2), &verifier), KeyApply::Refused(crate::peg::PegOutcome::Replay)), "⛔ REPLAY: the settled retire was taken again on the peer");
    }
}

/// ⭐⭐ SAFE AT SCALE, stage three — A DEPOSIT ADDRESS HAS ONE SOURCE: THE CHAIN'S KEY RECORD (spec §3f R2, make before
/// break; `Node::vault_keys_mintable`). Two nodes that apply the same key objects: A saw every member set live; C is
/// made to forget every set it saw (a node that joined later, or restarted) — it must judge the same addresses, from
/// the record's own inputs. Three custodians with real custody points; a co-signed Bitcoin deposit address.
///   • BEFORE ANY KEY (the chain as it was): the address served, and accepted, is the live set's leaf.
///   • THE THREE TAKE THEIR KEY: the same address — the key IS the live leaf.
///   • A CUSTODIAN IS SLASHED: the live leaf changes; the chain's key has not. The address a node SERVES is still the
///     recorded key's (a deposit never waits on a re-key); an address under the new live leaf — a set the chain has
///     not recorded as a key — is REFUSED on both nodes.
///   • THE TWO TAKE THEIR KEY: the served address is the new key's; the replaced key's address is still accepted
///     inside its window (it may have been handed out a moment ago) and REFUSED once the window has passed, on both.
#[test]
fn safe_at_scale_a_deposit_address_is_the_chains_current_keys_and_a_replaced_keys_only_inside_its_window() {
    use crate::node::objects::vault_key_tx::apply_chain_vault_key;
    use crate::vault_key_tx::{KeyApply, VaultKey, VaultKeyHeader};
    let (mut a, mut c) = (dd_node(), dd_node());
    let seats: Vec<Seat> = (0..3).map(seat).collect();
    for n in [&mut a, &mut c] {
        let mut gp = n.params().clone();
        gp.governance_set_stake_lock_blocks(0);
        gp.merge_depth_cap = 4;
        gp.governance_set_unbonding_blocks(0);
        n.set_params(gp);
        for s in &seats {
            bond(n, s);
        }
    }
    let verifier = crate::pqauth::MlDsaVerifier;
    let depositor = crate::btc_tx::xonly_pubkey(&[0x51u8; 32]).expect("a depositor key"); // CLASSICAL-CRYPTO-EXEMPT: a test depositor's Bitcoin key (bridge endpoint)
    let blind = lanes(&[0xd0, 0x0e, 7, 7]);
    let nonce = crate::spend_frontier::digest_to_lane_bytes(&blind);
    let served = |n: &Node| n.reserve_addresses(&nonce, Some(&depositor)).0.expect("a node with bonded custody serves a Bitcoin deposit address");
    let ours = |n: &Node, address: &str| n.reserve_address_is_vaults(0, address, &blind, Some(&depositor));
    // the address the LIVE seats' leaf would give, whatever the record says
    let live = |n: &Node| -> String {
        let leaf = crate::btc_tx::custody_leaf(&n.custody_members_of_vault(0)).expect("the live leaf");
        crate::btc_tx::reserve_address(crate::bridge::btc_hrp(), &crate::btc_tx::deposit_output(&leaf, &depositor, &nonce).expect("an output").output_x)
    };
    // the vault's seated members take the key of their set, the same object applied on both nodes
    let take = |a: &mut Node, c: &mut Node, signers: &[&Seat]| {
        let mut ids: Vec<[u8; 32]> = signers.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        let msg = a.peg().vault_key_take_msg(0, &a.vault_btc_key(0), &ids, b"");
        let key = VaultKey { header: VaultKeyHeader::Take { vault: 0, members: ids, xmr_address: Vec::new() }, attestors: sign(signers, &msg) };
        for n in [a, c] {
            assert!(matches!(apply_chain_vault_key(n, &key.wire(), Some(0), &verifier), KeyApply::Taken), "the vault's members take the key of their set");
        }
    };

    // BEFORE ANY KEY
    let three = served(&a);
    assert_eq!(three, live(&a));
    assert!(ours(&a, &three) && ours(&c, &three), "CALIBRATION: with no key recorded, the live set's address is ours, as it was");

    // THE THREE TAKE THEIR KEY
    take(&mut a, &mut c, &[&seats[0], &seats[1], &seats[2]]);
    assert_eq!(a.peg().vault_key_current(0).map(|k| k.btc.clone()), Some(a.vault_btc_key(0)), "the record holds the leaf and its inputs as the node's chain forms them");
    assert_eq!(served(&a), three, "the key is the live leaf: the same address");
    // C forgets every set it ever saw live: from here it judges from the record alone
    c.custody_leaf_ring.clear();

    // A CUSTODIAN IS SLASHED on both nodes
    for n in [&mut a, &mut c] {
        assert!(n.apply_slash(seats[2].id).is_some());
    }
    let two = live(&a);
    assert_ne!(two, three, "PRECONDITION: the live leaf changed with the set");
    for (n, name) in [(&a, "A"), (&c, "the node that forgot")] {
        assert_eq!(served(n), three, "⛔ {name} serves an address of a set the chain has not recorded as a key (a deposit must never wait on a re-key, nor land under a key nobody recorded)");
        assert!(ours(n, &three), "{name}: the recorded key's address is ours");
        assert!(!ours(n, &two), "⛔ {name} accepts a deposit address under a member set the chain does not name as a key");
    }

    // THE TWO TAKE THEIR KEY
    take(&mut a, &mut c, &[&seats[0], &seats[1]]);
    for (n, name) in [(&a, "A"), (&c, "the node that forgot")] {
        assert_eq!(served(n), two, "{name} serves the new key's address");
        assert!(ours(n, &two), "{name}: the new key's address is ours");
        assert!(ours(n, &three), "⛔ {name} refuses the replaced key's address inside its window: an address handed out a moment ago would mint nothing");
    }
    // A-F60: the replaced key's address window is a span of the chain's OWN CLOCK (median time past), never a count of
    // blocks — a chain runs at whatever rate its mesh reaches, not the target. So advance the clock: stamp each next block
    // later in wall-clock time and stop on the MEASURED tick, so how many blocks it takes (and the real block rate) does
    // not enter. The step here is a wall-clock increment for the fixture, not a claim about how fast blocks arrive.
    let mut ts = 5_000u64;
    let step = a.vault_key_window_ticks().saturating_mul(crate::dag::MESH_TARGET_SPACING_MS); // one window of clock per block → a few blocks carry MTP across it
    for _ in 0..(a.params().mtp_sample_len as u64 + 6) {
        if a.chain_tick() >= a.vault_key_window_ticks() {
            break;
        }
        ts += step;
        let blk = a.produce(ts, Hash32::hash(b"key-door"), Hash32::hash(b"key-door-mc")).expect("A produces");
        let _ = c.ingest_block(blk, ts);
    }
    let _ = a.fold_past_for_test(&mut [&mut c], ts, b"key-door-fold");
    assert!(a.chain_tick() >= a.vault_key_window_ticks(), "PRECONDITION: the chain's clock has passed the window at the tip");
    for (n, name) in [(&a, "A"), (&c, "the node that forgot")] {
        assert!(!ours(n, &three), "⛔ {name} still mints to a replaced key's address after its window");
        assert!(ours(n, &two) && served(n) == two, "{name}: the current key's address stays ours");
    }
}

/// ⭐⭐ SAFE AT SCALE, stage three — A KEY IS ITS MEMBERS AND ITS LEAF: BOND WEIGHT THAT MOVES NO SLOT TAKES NO KEY
/// (finding A-F33, lane vaults 2026-11-11, read in code while designing the rotation).
/// A vault's Bitcoin leaf spreads its members' bond weights over sixty key slots (`btc_tx::custody_slots`), so most
/// weight changes — every small delegation — leave the leaf, and so every deposit address, exactly as it was. The take
/// rule compared the whole `VaultBtcKey` (the leaf AND the raw weights the record keeps beside it): one unit of
/// delegated weight made the vault owe a take to the SAME leaf. The replaced row then shared the current key's leaf, so
/// the retire rule (no coin under that leaf on the signer's own source) could never be signed while the current key
/// held a coin; the record climbed to `VAULT_KEYS_ALIVE_MAX`, no later take was accepted, and a leaver named by a stuck
/// row was held by the release gate (R4) with nothing able to free it.
/// Two nodes (A acts as a custodian; C only holds the chain), three custodians with real custody points:
///   • CALIBRATION: one unit delegated moves no slot — the leaf is the same, the record's weights are not;
///   • the custodian's node says its vault owes NO key, and the same-leaf take, signed by the whole vault, is a REPLAY
///     on the peer: the record keeps one row;
///   • CONTROL: weight that moves a slot is a new leaf — the take is due, and applies on the peer.
/// TWO-PARTY-REVIEWED: every take is applied on C from the object's bytes; A is the custodian whose node decides what
/// its vault owes.
#[test]
fn safe_at_scale_bond_weight_that_moves_no_slot_of_the_leaf_takes_no_key_and_weight_that_moves_one_does() {
    use crate::node::objects::vault_key_tx::apply_chain_vault_key;
    use crate::vault_key_tx::{KeyApply, VaultKey, VaultKeyHeader};
    let (mut a, mut c) = (dd_node(), dd_node());
    let seats: Vec<Seat> = (0..3).map(seat).collect();
    for n in [&mut a, &mut c] {
        let mut gp = n.params().clone();
        gp.governance_set_stake_lock_blocks(0);
        gp.merge_depth_cap = 4;
        gp.governance_set_unbonding_blocks(0);
        n.set_params(gp);
        for s in &seats {
            bond(n, s);
        }
        // unequal weights, so no member sits on a slot boundary: 6000, 5000, 5000 of 16000 are 22, 18 and 18 slots
        n.validators.delegate(seats[0].id, 1_000).expect("a delegation to a seated custodian");
    }
    let verifier = crate::pqauth::MlDsaVerifier;
    let mut ids: Vec<[u8; 32]> = seats.iter().map(|s| s.id).collect();
    ids.sort_unstable();
    let all: Vec<&Seat> = seats.iter().collect();
    let take_now = |n: &Node| -> VaultKey {
        let msg = n.peg().vault_key_take_msg(0, &n.vault_btc_key(0), &ids, b"");
        VaultKey { header: VaultKeyHeader::Take { vault: 0, members: ids.clone(), xmr_address: Vec::new() }, attestors: sign(&all, &msg) }
    };
    let first = take_now(&a);
    for n in [&mut a, &mut c] {
        assert!(matches!(apply_chain_vault_key(n, &first.wire(), Some(0), &verifier), KeyApply::Taken), "the vault's members take the key of their set");
    }
    a.set_custodian_identity(seats[1].id, Vec::new());
    assert_eq!(a.vault_key_take_due(false, None), None, "CONTROL: a vault whose key is its members' and its leaf owes none");
    let before = a.vault_btc_key(0);

    // ONE UNIT OF DELEGATED WEIGHT: no slot moves
    for n in [&mut a, &mut c] {
        n.validators.delegate(seats[1].id, 1).expect("a delegation");
    }
    let after = a.vault_btc_key(0);
    assert_eq!(after.leaf, before.leaf, "CALIBRATION: one unit of weight moves no slot — the leaf, and every deposit address, is the same");
    assert_ne!(after.members, before.members, "CALIBRATION: the weights the record keeps beside the leaf differ");
    let owed = a.vault_key_take_due(false, None);
    let same_leaf = take_now(&c);
    let verdict = apply_chain_vault_key(&mut c, &same_leaf.wire(), Some(1), &verifier);
    eprintln!(
        "[vault-key] after one unit of delegated weight (same leaf): the custodian's node says its vault owes {}; a take of the same members and leaf signed by the whole vault is {verdict:?} on the peer; its rows (replaced?) are now {:?}",
        if owed.is_some() { "A TAKE" } else { "nothing" },
        c.peg().vault_keys(0).iter().map(|k| k.replaced_tick.is_some()).collect::<Vec<_>>()
    );
    assert_eq!(owed, None, "⛔ a weight change that moves no slot made the vault owe a key to the SAME leaf");
    assert!(matches!(verdict, KeyApply::Refused(crate::peg::PegOutcome::Replay)), "⛔ the peer took a second key with the current key's own leaf: {verdict:?}");
    assert_eq!(c.peg().vault_keys(0).len(), 1, "⛔ the peer's record holds a replaced row that shares the current key's leaf (it could never be retired while that key holds a coin)");

    // CONTROL: WEIGHT THAT MOVES A SLOT is a new leaf, and a new key
    for n in [&mut a, &mut c] {
        n.validators.delegate(seats[2].id, 4_000).expect("a delegation");
    }
    assert_ne!(a.vault_btc_key(0).leaf, before.leaf, "PRECONDITION: this much weight moves slots — another leaf");
    assert!(matches!(a.vault_key_take_due(false, None), Some(VaultKeyHeader::Take { .. })), "a new leaf is a key the vault owes");
    let moved = take_now(&c);
    assert!(matches!(apply_chain_vault_key(&mut c, &moved.wire(), Some(2), &verifier), KeyApply::Taken), "the peer takes the new leaf's key");
    assert_eq!(c.peg().vault_keys(0).iter().map(|k| k.replaced_tick.is_some()).collect::<Vec<_>>(), vec![true, false], "the old key is replaced, the new one current");
}

/// ⭐ SAFE AT SCALE, stage three (spec §3f R2, as it holds for Monero) — A NODE HANDS OUT A MONERO DEPOSIT ADDRESS ONLY
/// OF THE WALLET ITS VAULT'S SEATS KEEP OPEN. A Monero deposit can only be seen by the wallet it is paid to, and a mint
/// needs two thirds of the vault's seats to see it. Two nodes (A, and C which only holds the chain), three custodians:
///   • with the key of the three recorded and the three seated: both nodes serve that key's wallet address;
///   • one custodian leaves (the chain still records the three's key as current): BOTH NODES SERVE NOTHING — a buy
///     waits for the re-key instead of paying a wallet the seats no longer share;
///   • an address handed out before the change is still judged the vault's own at the attest door (the members that
///     stayed read the old wallet on their visits), so a payment already on its way is not refused;
///   • the two that stayed take their key with their own wallet's address: both nodes serve the new address.
/// TWO-PARTY-REVIEWED: A applies the key objects and C applies the same bytes; every served address is asserted on C.
#[test]
fn safe_at_scale_a_monero_deposit_address_is_served_only_of_the_wallet_the_vaults_seats_keep_open() {
    use crate::node::objects::vault_key_tx::apply_chain_vault_key;
    use crate::vault_key_tx::{KeyApply, VaultKey, VaultKeyHeader};
    let (mut a, mut c) = (dd_node(), dd_node());
    let seats: Vec<Seat> = (0..3).map(seat).collect();
    for n in [&mut a, &mut c] {
        for s in &seats {
            bond(n, s);
        }
    }
    let verifier = crate::pqauth::MlDsaVerifier;
    let wallet = |tag: u8| crate::bridge::encode_monero_address(crate::bridge::xmr_net_byte(), &[tag; 32], &[tag ^ 0x55; 32]);
    let take = |a: &mut Node, c: &mut Node, signers: &[&Seat], address: &str, blue: u64| -> [u8; 32] {
        let mut ids: Vec<[u8; 32]> = signers.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        let msg = a.peg().vault_key_take_msg(0, &a.vault_btc_key(0), &ids, address.as_bytes());
        let key = VaultKey { header: VaultKeyHeader::Take { vault: 0, members: ids.clone(), xmr_address: address.as_bytes().to_vec() }, attestors: sign(signers, &msg) };
        for n in [a, c] {
            assert!(matches!(apply_chain_vault_key(n, &key.wire(), Some(blue), &verifier), KeyApply::Taken), "the vault's members take the key of their set");
        }
        crate::xmr_custody::set_id(&ids)
    };
    let blind = lanes(&[0xd0, 0x0e, 9, 9]);
    let nonce = crate::spend_frontier::digest_to_lane_bytes(&blind);
    let integrated = |sid: &[u8; 32], main: &str| crate::bridge::xmr_integrated_address(main, &crate::xmr_custody::payment_id(sid, &nonce)).expect("an integrated address");

    // the three seated, their key recorded
    let (w1, w2) = (wallet(0x11), wallet(0x22));
    let sid1 = take(&mut a, &mut c, &[&seats[0], &seats[1], &seats[2]], &w1, 0);
    let first = integrated(&sid1, &w1);
    for (n, name) in [(&a, "A"), (&c, "the peer")] {
        assert_eq!(n.xmr_reserve_address_for_nonce(&nonce), Some(first.clone()), "{name} serves the recorded key's wallet while its members are the vault's seats");
    }

    // a custodian leaves: the record still names the three's key as current
    for n in [&mut a, &mut c] {
        assert!(n.validators.remove_exiting_at(&seats[2].id, None).is_some());
    }
    for (n, name) in [(&a, "A"), (&c, "the peer")] {
        assert_eq!(n.peg().vault_key_current(0).map(|k| k.members.len()), Some(3), "PRECONDITION: the chain still records the three's key as current");
        assert_eq!(n.xmr_reserve_address_for_nonce(&nonce), None, "⛔ {name} handed out a Monero address of a wallet the vault's seats no longer share — a deposit there is seen by its old members only and may never be minted");
        assert!(n.xmr_reserve_address_is_vaults_own(0, &first, &blind), "{name}: an address handed out before the change is still the vault's own at the attest door");
    }

    // the two that stayed take their key, with their own wallet's address
    let sid2 = take(&mut a, &mut c, &[&seats[0], &seats[1]], &w2, 1);
    let second = integrated(&sid2, &w2);
    assert_ne!(first, second);
    for (n, name) in [(&a, "A"), (&c, "the peer")] {
        assert_eq!(n.xmr_reserve_address_for_nonce(&nonce), Some(second.clone()), "{name} serves the new key's wallet once the chain records it");
        assert!(n.xmr_reserve_address_is_vaults_own(0, &first, &blind), "{name}: the replaced key's address stays the vault's own inside its window");
    }
}

/// The Bitcoin custody secret of fixture seat `i` (`seat`): what its lane signs with.
fn seat_secret(i: u8) -> [u8; 32] {
    let mut secret = [0x35u8; 32];
    secret[0] = i + 1;
    secret
}

/// ⭐⭐ SAFE AT SCALE, stage three (spec §3f R3; finding A-F21) — A REPLACED KEY'S COINS MOVE ONLY TO THE VAULT'S CURRENT
/// KEY, ONLY WHEN DUE, AND THE FEE IS JUDGED FROM BITCOIN ITSELF. Three custodians hold a vault under key K1 with two
/// reserve coins on a simulated Bitcoin chain (real taproot script-path spends, verified by the chain). One leaves
/// (not slashed): the two that stay take K2, and K1 is a replaced key that still holds the coins and still names the
/// leaver. Two custodians' own lanes (A as seat 0, B as seat 1), each with its own book and node:
///   • NOT DUE at a high fee: A proposes nothing, and B refuses the honest proposal (its own reading is not low).
///   • DUE at a low fee: A proposes; B refuses every lie about it — another destination, an overstated input, a fee
///     past the ceiling, a coin already under the current key as an input, a leg — and signs the honest one.
///   • Two of K1's three sign; Bitcoin accepts the spend; both books follow: the old addresses leave, the coin stands
///     at K2's HOME address (derived from the chain's record alone), worth the inputs less the fee.
///   • THE FEE, judged by a custodian that saw none of it (an empty book): from the evidence, its own chain's record
///     and its own Bitcoin source it derives the same ledger, fee and transaction — and refuses an overstated input
///     with the fee raised to match (the same Bitcoin transaction), a wrong nonce, and another destination.
///   • THE COIN LIST: a custodian with an empty book asks; the one whose round it is answers sealed to its key; it
///     books exactly the addresses that derive under a key its chain records AND hold a coin on its own source — a
///     made-up entry and an entry under a key the chain does not record book nothing.
///   • A SLASHED KEY HOLDER makes the move due AT ONCE: seat 1 is slashed, seat 0 takes K3 alone, and K2's coins move
///     at the same high fee that was refused above — signed by seat 1's own lane, a key holder the chain no longer
///     seats, which judges that one kind of proposal and signs it.
/// TWO-PARTY-REVIEWED: two custodians' lanes over two nodes; every acceptance and refusal is asserted on the lane that
/// did NOT author the proposal, and the result is asserted on Bitcoin (the simulated chain's own coins).
#[test]
fn safe_at_scale_a_replaced_keys_coins_move_only_to_the_vaults_current_key_when_due_and_the_fee_is_judged_from_bitcoin() {
    use crate::btc_payout::{CoinAddress, CoinShare, CostEvidence, PayoutLane, PayoutProposal, COIN_SHARE_BODY_MAX, TEST_BRIDGE_SECRET};
    use crate::node::objects::vault_key_tx::apply_chain_vault_key;
    use crate::protocol::WireMsg;
    use crate::vault_key_tx::{KeyApply, VaultKey, VaultKeyHeader};
    let _serial = crate::btc_sim::serial().lock().unwrap_or_else(|e| e.into_inner());
    let world = crate::btc_sim::install(crate::btc_sim::SimBitcoin::new(11));
    let (mut a, mut b) = (dd_node(), dd_node());
    let seats: Vec<Seat> = (0..3).map(seat).collect();
    for n in [&mut a, &mut b] {
        for s in &seats {
            bond(n, s);
        }
    }
    // node A is custodian 0's, node B is custodian 1's
    a.set_custodian_identity(seats[0].id, seats[0].dk.clone());
    b.set_custodian_identity(seats[1].id, seats[1].dk.clone());
    let verifier = crate::pqauth::MlDsaVerifier;
    let act = |i: u8| TEST_BRIDGE_SECRET.with(|c| c.set(Some(seat_secret(i))));
    let x = |i: u8| crate::btc_tx::xonly_pubkey(&seat_secret(i)).expect("a custody point"); // CLASSICAL-CRYPTO-EXEMPT: a test custodian's Bitcoin custody point (bridge endpoint)
    let take = |a: &mut Node, b: &mut Node, signers: &[&Seat], blue: u64| {
        let mut ids: Vec<[u8; 32]> = signers.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        let msg = a.peg().vault_key_take_msg(0, &a.vault_btc_key(0), &ids, b"");
        let key = VaultKey { header: VaultKeyHeader::Take { vault: 0, members: ids, xmr_address: Vec::new() }, attestors: sign(signers, &msg) };
        for n in [a, b] {
            assert!(matches!(apply_chain_vault_key(n, &key.wire(), Some(blue), &verifier), KeyApply::Taken), "the vault's members take the key of their set");
        }
    };
    let tmp = |tag: &str| std::env::temp_dir().join(format!("vaults-consolidation-{}-{tag}.bin", std::process::id()));

    // K1: the three. Two reserve coins under it, on Bitcoin.
    take(&mut a, &mut b, &[&seats[0], &seats[1], &seats[2]], 0);
    let k1 = a.peg().vault_key_current(0).expect("K1").btc.clone();
    let (mut lane_a, mut lane_b) = (PayoutLane::for_test(tmp("a")), PayoutLane::for_test(tmp("b")));
    let (n1, n2) = ([0xa1u8; 32], [0xa2u8; 32]);
    let c1 = lane_a.book_coin_for_test(&k1.members, &n1);
    let c2 = lane_a.book_coin_for_test(&k1.members, &n2);
    assert_eq!((lane_b.book_coin_for_test(&k1.members, &n1), lane_b.book_coin_for_test(&k1.members, &n2)), (c1.clone(), c2.clone()), "both custodians derive the same coin addresses");
    world.chain().fund(&c1, 60_000).expect("coin 1");
    world.chain().fund(&c2, 40_000).expect("coin 2");
    world.chain().mine(1);

    // SEAT 2 LEAVES (not slashed); the two that stay take K2
    for n in [&mut a, &mut b] {
        assert!(n.validators.remove_exiting_at(&seats[2].id, None).is_some());
    }
    take(&mut a, &mut b, &[&seats[0], &seats[1]], 1);
    let k2 = a.peg().vault_key_current(0).expect("K2").clone();
    assert_ne!(k2.btc.leaf, k1.leaf, "PRECONDITION: the two's key is another leaf");
    let (_, home_nonce, home) = Node::vault_key_home_btc(&k2).expect("K2's home derives from the record");
    assert_eq!(Node::vault_key_home_btc(b.peg().vault_key_current(0).expect("K2 on B")).map(|h| h.2), Some(home.clone()), "every node derives the same home from its own chain");
    act(0);
    lane_a.book_homes_for_test(&a);
    act(1);
    lane_b.book_homes_for_test(&b);
    assert!(lane_a.book().addresses.contains_key(&home) && lane_b.book().addresses.contains_key(&home), "each custodian books its key's home from the record");
    // a coin already under the current key (a payout's change would land here)
    world.chain().fund(&home, 30_000).expect("a coin at home");
    world.chain().mine(1);

    // whose turn among K1's holders, in key order
    let mut holders: Vec<[u8; 32]> = k1.members.iter().map(|(p, _)| *p).collect();
    holders.sort_unstable();
    let turn_of = |i: u8| holders.iter().position(|p| *p == x(i)).expect("a holder of K1") as u64;
    let ring = [10u64; 6];
    lane_a.seed_fee_ring_for_test(&ring);
    lane_b.seed_fee_ring_for_test(&ring);

    // NOT DUE at a high fee
    world.chain().set_fee_rate_sat_vb(20);
    act(0);
    assert!(lane_a.propose_consolidation_for_test(&a, 1_000, turn_of(0)).is_empty(), "⛔ a consolidation was proposed at a fee above this node's own trailing median, with no key past its deadline");

    // DUE at a low fee: A proposes and signs
    world.chain().set_fee_rate_sat_vb(5);
    assert!(lane_a.propose_consolidation_for_test(&a, 1_000, turn_of(0) + 1).is_empty(), "⛔ a custodian proposed out of its turn");
    let out = lane_a.propose_consolidation_for_test(&a, 1_000, turn_of(0));
    let (Some(WireMsg::PayoutProposal(p_bytes)), Some(WireMsg::PayoutSig(a_sig))) = (out.first().cloned(), out.get(1).cloned()) else {
        panic!("⛔ the holder whose turn it is did not propose and sign the consolidation at a low fee: {} message(s)", out.len());
    };
    let p = PayoutProposal::decode(&p_bytes).expect("the proposal decodes");
    assert!(p.legs.is_empty() && p.decoys.is_empty() && p.inputs.len() == 2, "two coins, no legs, no decoys");
    assert_eq!(p.change_nonce, home_nonce, "the proposal names the current key's home by its public nonce");
    let fee = p.fee_sats;

    // B REFUSES EVERY LIE (its own reading is low: each is refused for what it says, not for the fee market)
    act(1);
    let refused = |lane_b: &mut PayoutLane, b: &Node, lie: &PayoutProposal, what: &str| {
        let (fresh, out) = lane_b.on_proposal(&lie.encode().expect("encodes"), b, 1_000);
        assert!(!fresh && out.is_empty() && lane_b.slot_count_for_test() == 0, "⛔ {what}: the second custodian signed or relayed it");
    };
    refused(&mut lane_b, &b, &PayoutProposal { change_nonce: [9u8; 32], ..p.clone() }, "REDIRECT (an output that is not the current key's home)");
    let mut lie = p.clone();
    lie.inputs[0].value_sats += 1;
    refused(&mut lane_b, &b, &lie, "OVERSTATED INPUT");
    refused(&mut lane_b, &b, &PayoutProposal { fee_sats: fee * 5, ..p.clone() }, "A FEE PAST THE CEILING (five times this node's own estimate; the ceiling is four)");
    let at_home = world.chain().utxos(&home).expect("home answers")[0].clone();
    let mut lie = p.clone();
    lie.inputs.push(crate::btc_payout::PayoutInput { txid: at_home.txid, vout: at_home.vout, value_sats: at_home.value_sats, address: home.clone() });
    refused(&mut lane_b, &b, &lie, "A COIN ALREADY UNDER THE CURRENT KEY spent again (a fee for nothing)");
    refused(&mut lane_b, &b, &PayoutProposal { legs: vec![[7u8; 32]], ..p.clone() }, "A LEG nobody is owed, riding the consolidation's coins");
    // …and the honest one while B's own reading is NOT low
    world.chain().set_fee_rate_sat_vb(20);
    refused(&mut lane_b, &b, &p, "NOT DUE (the fee is above the signer's own trailing median and no key is past its deadline)");

    // THE HONEST PROPOSAL AT A LOW FEE: B signs, two of three reach Bitcoin
    world.chain().set_fee_rate_sat_vb(5);
    let (fresh, out) = lane_b.on_proposal(&p_bytes, &b, 1_000);
    let Some(WireMsg::PayoutSig(b_sig)) = out.first().cloned() else { panic!("⛔ the second custodian did not sign the honest consolidation (fresh {fresh})") };
    assert!(lane_b.on_sig(&a_sig, &b, 1_000).0, "B counts A's signature");
    act(0);
    assert!(lane_a.on_sig(&b_sig, &a, 1_000).0, "A counts B's signature");
    assert_eq!(world.chain().mempool_len(), 1, "⛔ Bitcoin did not take the consolidation signed by two of K1's three");
    world.chain().mine(1);
    lane_a.settle_for_test(&mut a);
    act(1);
    lane_b.settle_for_test(&mut b);
    let at_home = world.chain().utxos(&home).expect("home answers");
    assert!(at_home.iter().any(|c| c.value_sats == 100_000 - fee), "⛔ BITCOIN: the current key's home does not hold the two coins' value less the fee: {:?}", at_home.iter().map(|c| c.value_sats).collect::<Vec<_>>());
    assert!(world.chain().utxos(&c1).is_some_and(|c| c.is_empty()) && world.chain().utxos(&c2).is_some_and(|c| c.is_empty()), "the replaced key holds no coin");
    for (lane, name) in [(&lane_a, "A"), (&lane_b, "B")] {
        assert!(!lane.book().addresses.contains_key(&c1) && !lane.book().addresses.contains_key(&c2), "{name}'s book dropped the spent addresses");
        assert!(lane.book().addresses.contains_key(&home), "{name}'s book holds the home");
        assert_eq!(lane.book().costs.len(), 1, "⛔ {name} kept no evidence of the fee that left custody (A-F21)");
    }
    let (txid, evidence) = lane_a.book().costs.iter().next().map(|(t, e)| (*t, e.clone())).expect("A's evidence");
    assert_eq!(lane_b.book().costs.get(&txid), Some(&evidence), "both custodians hold the same evidence");
    let seen = lane_a.scan_for_test(&mut a).expect("every address answered").0;
    assert!(seen.contains(&k2.btc.leaf) && !seen.contains(&k1.leaf), "⛔ the custodian's own source still shows a coin under the replaced key (or none under the current one)");

    // THE FEE, JUDGED BY A CUSTODIAN THAT SAW NONE OF IT (an empty book; its own chain and its own source)
    let newcomer = PayoutLane::for_test(tmp("n"));
    assert_eq!(newcomer.judge_cost_for_test(&evidence, &b), Some((crate::peg::NATIVE_PEG_ASSET_ID, fee, txid)), "⛔ a custodian that never saw the move does not derive its fee from the evidence, its chain and its Bitcoin source");
    let (ep, ecoins) = CostEvidence::decode(&evidence).expect("the evidence decodes");
    let enc = |p: &PayoutProposal, coins: &[CoinAddress]| CostEvidence { proposal: p.encode().expect("encodes"), coins: coins.to_vec(), rebalance_out: None }.encode();
    let mut lie = ep.clone();
    lie.inputs[0].value_sats += 5_000;
    lie.fee_sats += 5_000; // the SAME Bitcoin transaction: outpoints and output unchanged, a bigger fee claimed
    assert_eq!(newcomer.judge_cost_for_test(&enc(&lie, &ecoins), &b), None, "⛔ LYING PROVER: a fee overstated by an overstated input was judged true");
    let mut wrong = ecoins.clone();
    wrong[0].nonce = vec![0xeeu8; 32];
    assert_eq!(newcomer.judge_cost_for_test(&enc(&ep, &wrong), &b), None, "⛔ an input that does not derive under the vault's recorded key was judged the vault's");
    assert_eq!(newcomer.judge_cost_for_test(&enc(&PayoutProposal { change_nonce: [9u8; 32], ..ep.clone() }, &ecoins), &b), None, "⛔ a move to an address that is no home of this vault was judged a cost of it");

    // THE COIN LIST: an empty book asks, the custodian whose round it is answers, only true entries are booked
    let mut joiner = PayoutLane::for_test(tmp("j"));
    act(0);
    let ask = CoinShare::Ask { vault: 0, from: seats[1].id, round: 0 }.encode();
    // A-F30: the runtime hands the lane the custodian that SIGNED the message; an ask in another's name is dropped
    assert_eq!(lane_a.on_coin_share(&ask, seats[0].id, &a, 1_900), (false, Vec::new()), "⛔ an ask naming another custodian than its signer was read or relayed");
    let (_, gives) = lane_a.on_coin_share(&ask, seats[1].id, &a, 2_000);
    let Some(WireMsg::CoinShare(give)) = gives.first().cloned() else { panic!("⛔ the vault's other custodian did not answer the ask") };
    assert!(lane_a.on_coin_share(&ask, seats[1].id, &a, 2_500).1.is_empty(), "one answer per asker per period");
    act(1);
    let _ = joiner.on_coin_share(&give, seats[0].id, &b, 2_000);
    assert!(joiner.book().addresses.contains_key(&home), "⛔ the asker did not book the vault's funded home from the sealed list");
    let before = joiner.book().addresses.len();
    let lies = vec![
        CoinAddress { nonce: vec![0xeeu8; 32], leaf_hash: k2.btc.leaf }, // derives, but nobody paid it
        CoinAddress { nonce: home_nonce.to_vec(), leaf_hash: [0x77u8; 32] }, // a key the chain does not record
    ];
    let sealed = a.seal_to_vault_custodian(&seats[1].id, &postcard::to_allocvec(&lies).expect("encodes"), COIN_SHARE_BODY_MAX).expect("A seals to its vault's custodian");
    let _ = joiner.on_coin_share(&CoinShare::Give { to: seats[1].id, sealed }.encode(), seats[0].id, &b, 2_000);
    assert_eq!(joiner.book().addresses.len(), before, "⛔ LYING GIVER: a made-up coin entry was booked");

    // A SLASHED KEY HOLDER: the move is due AT ONCE, and a key holder the chain no longer seats signs it
    for n in [&mut a, &mut b] {
        assert!(n.apply_slash(seats[1].id).is_some());
    }
    take(&mut a, &mut b, &[&seats[0]], 2);
    let k3 = a.peg().vault_key_current(0).expect("K3").clone();
    let (_, _, home3) = Node::vault_key_home_btc(&k3).expect("K3's home");
    assert!(b.custodian_id().is_none(), "PRECONDITION: the chain no longer seats the slashed custodian");
    assert!(a.vault_key_move_urgent(0, &k2.btc.leaf) && !a.vault_key_move_urgent(0, &k3.btc.leaf), "a key that names a slashed custodian is due at once; the current key is not");
    world.chain().set_fee_rate_sat_vb(20);
    let mut h2: Vec<[u8; 32]> = k2.btc.members.iter().map(|(p, _)| *p).collect();
    h2.sort_unstable();
    act(0);
    lane_a.book_homes_for_test(&a);
    let out = lane_a.propose_consolidation_for_test(&a, 3_000, h2.iter().position(|p| *p == x(0)).expect("seat 0 holds K2") as u64);
    let (Some(WireMsg::PayoutProposal(p2)), Some(WireMsg::PayoutSig(a2))) = (out.first().cloned(), out.get(1).cloned()) else {
        panic!("⛔ URGENT: the move of a slashed key holder's coins was not proposed at a high fee: {} message(s)", out.len());
    };
    act(1);
    let (_, out) = lane_b.on_proposal(&p2, &b, 3_000);
    let Some(WireMsg::PayoutSig(b2)) = out.first().cloned() else { panic!("⛔ the slashed key holder's own lane did not sign the move of its old key's coins") };
    act(0);
    assert!(lane_a.on_sig(&b2, &a, 3_000).0);
    act(1);
    let _ = lane_b.on_sig(&a2, &b, 3_000);
    world.chain().mine(1);
    assert!(world.chain().utxos(&home).is_some_and(|c| c.is_empty()), "⛔ BITCOIN: coins still stand under the key that names a slashed custodian");
    assert!(world.chain().utxos(&home3).is_some_and(|c| c.len() == 1), "the vault's coins stand under its current key's home");
    TEST_BRIDGE_SECRET.with(|c| c.set(None));
    for tag in ["a", "b", "n", "j"] {
        let _ = std::fs::remove_file(tmp(tag));
    }
}

/// Form one k-of-n Monero custody wallet among `wallets` (each already has the set's wallet open): the exchange the
/// custody lane drives over the mesh, here in one loop. Returns the account's address.
fn xmr_form(wallets: &[&crate::xmr_rpc::WalletRpc]) -> String {
    let k = crate::xmr_custody::threshold(wallets.len());
    let mut infos: Vec<String> = wallets.iter().map(|w| w.prepare_multisig().expect("prepare")).collect();
    for round in 0..8u8 {
        let mut next = Vec::with_capacity(wallets.len());
        for (i, w) in wallets.iter().enumerate() {
            let others: Vec<String> = infos.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, s)| s.clone()).collect();
            next.push(if round == 0 { w.make_multisig(&others, k, "").expect("make") } else { w.exchange_multisig_keys(&others, "").expect("exchange") });
        }
        if wallets.iter().all(|w| matches!(w.is_multisig(), Ok((true, true, _, _)))) {
            return wallets[0].address().expect("the account's address");
        }
        infos = next;
    }
    panic!("the wallets did not finish their exchange");
}

/// ⭐⭐ SAFE AT SCALE, stage three (spec §3f R3; findings A-F20, A-F21) — A REPLACED KEY'S MONERO WALLET IS SWEPT TO THE
/// VAULT'S CURRENT KEY, AND ITS FEE IS JUDGED BY A CUSTODIAN THAT NEVER HELD THAT WALLET. A simulated Monero chain with
/// one wallet per member set (as real custody keeps them). Three custodians hold wallet W1 (2 of 3) with 5 XMR; one
/// leaves and a new one bonds; the new set holds wallet W2 and the chain records both keys with their addresses.
/// Each custodian has its own lane and its own wallet-rpc; two nodes hold the chain.
///   • A DEPOSIT PAID TO THE REPLACED KEY'S ADDRESS (valid inside its window): read from the current set's wallet it
///     is never seen (the hole, calibrated); one visit to the old key's wallet reads it.
///   • A LYING PROPOSER: the old set's own proposer builds and signs a sweep to ANOTHER address — the next signer
///     reads the set on its own wallet and signs nothing; Monero sees nothing. A message signed by a stranger to the
///     old set is not kept or relayed.
///   • THE HONEST SWEEP, at once: built by the old set's proposer, signed by the next member — the custodian that
///     LEFT signs as a key holder when the turn is its own — and relayed; W2 receives the 6 XMR less the fee and W1
///     is empty.
///   • THE FEE: each old member states what its own old wallet shows. With ONE statement the newcomer — it holds W2
///     only — judges nothing; with two thirds of the old set it derives the ledger, the fee and the transaction from
///     its own wallet. A fee one atom higher, and a transaction its wallet never received, are judged false.
/// TWO-PARTY-REVIEWED: four custodians' lanes and wallets over two nodes; every refusal is asserted on a lane that did
/// not author the message, and the result is asserted on Monero (the simulated chain's own balances).
#[test]
fn safe_at_scale_a_replaced_keys_monero_is_swept_to_the_vaults_current_key_and_a_newcomer_judges_the_fee_on_its_own_wallet() {
    use crate::node::objects::vault_key_tx::apply_chain_vault_key;
    use crate::protocol::WireMsg;
    use crate::vault_key_tx::{KeyApply, VaultKey, VaultKeyHeader};
    use crate::xmr_custody::{set_id, wallet_name};
    use crate::xmr_rpc::WalletRpc;
    use crate::xmr_sweep::{SweepLane, SweepMsg, XmrCostEvidence};
    const XMR: u64 = crate::xmr_rpc::XMR_ATOMIC_PER_XMR;
    let _serial = crate::xmr_sim::serial().lock().unwrap_or_else(|e| e.into_inner());
    let world = crate::xmr_sim::install(crate::xmr_sim::SimMonero::new(0x5eed_2026_1111));
    let (mut x, mut y) = (dd_node(), dd_node());
    let seats: Vec<Seat> = (0..4).map(seat).collect();
    for n in [&mut x, &mut y] {
        let mut gp = n.params().clone();
        gp.governance_set_stake_lock_blocks(0);
        gp.merge_depth_cap = 4;
        gp.governance_set_unbonding_blocks(0); // the address window is one block
        n.set_params(gp);
        for s in &seats[..3] {
            bond(n, s);
        }
    }
    let verifier = crate::pqauth::MlDsaVerifier;
    let take = |x: &mut Node, y: &mut Node, signers: &[&Seat], address: &str, blue: u64| -> Vec<[u8; 32]> {
        let mut ids: Vec<[u8; 32]> = signers.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        let msg = x.peg().vault_key_take_msg(0, &x.vault_btc_key(0), &ids, address.as_bytes());
        let key = VaultKey { header: VaultKeyHeader::Take { vault: 0, members: ids.clone(), xmr_address: address.as_bytes().to_vec() }, attestors: sign(signers, &msg) };
        for n in [x, y] {
            assert!(matches!(apply_chain_vault_key(n, &key.wire(), Some(blue), &verifier), KeyApply::Taken), "the vault's members take the key of their set");
        }
        ids
    };
    // each custodian's own wallet-rpc
    let rpc: Vec<WalletRpc> = (0..4).map(|_| WalletRpc::from_env().expect("the simulated Monero answers")).collect();
    let mut ids1: Vec<[u8; 32]> = seats[..3].iter().map(|s| s.id).collect();
    ids1.sort_unstable();
    let (sid1, name1) = (set_id(&ids1), wallet_name(&set_id(&ids1)));
    for w in &rpc[..3] {
        w.open_or_create(&name1, "").expect("the first set's wallet");
    }
    let w1 = xmr_form(&[&rpc[0], &rpc[1], &rpc[2]]);
    assert_eq!(take(&mut x, &mut y, &[&seats[0], &seats[1], &seats[2]], &w1, 0), ids1);
    world.chain().fund(&w1, 5 * XMR).expect("the reserve's Monero");
    world.chain().mine(crate::xmr_sim::SPEND_LOCK_BLOCKS);

    // custodian 2 leaves, custodian 3 bonds: the new set forms its own wallet, and the chain records its key
    for n in [&mut x, &mut y] {
        assert!(n.validators.remove_exiting_at(&seats[2].id, None).is_some());
        bond(n, &seats[3]);
    }
    let mut ids2: Vec<[u8; 32]> = [&seats[0], &seats[1], &seats[3]].iter().map(|s| s.id).collect();
    ids2.sort_unstable();
    let name2 = wallet_name(&set_id(&ids2));
    for w in [&rpc[0], &rpc[1], &rpc[3]] {
        w.open_or_create(&name2, "").expect("the second set's wallet");
    }
    let w2 = xmr_form(&[&rpc[0], &rpc[1], &rpc[3]]);
    assert_ne!(w1, w2, "PRECONDITION: the new set's wallet is another wallet (one wallet per member set)");
    assert_eq!(rpc[0].balance().map(|b| b.0), Ok(0), "⛔ A-F20 not reproduced: the new set's wallet already holds the old set's coins");
    take(&mut x, &mut y, &[&seats[0], &seats[1], &seats[3]], &w2, 1);

    // each custodian's lane: (its node, its seat, its wallet-rpc, the wallet its other lanes expect open)
    let mut lanes: Vec<SweepLane> = (0..4).map(|_| SweepLane::new()).collect();
    let node_of = |i: usize| if i % 2 == 0 { 0 } else { 1 }; // custodians 0 and 2 on X, 1 and 3 on Y
    let current = |i: usize| (i != 2).then(|| name2.clone());
    let key = |i: usize| Some((seats[i].pk.as_slice(), seats[i].sk.as_slice()));
    let mut now = 10_000u64;
    // one poll of every lane, every message delivered to every other lane; returns the rounds said in it
    let poll = |lanes: &mut Vec<SweepLane>, x: &Node, y: &Node, now: u64| -> Vec<SweepMsg> {
        let mut said = Vec::new();
        for i in 0..4 {
            let node = if node_of(i) == 0 { x } else { y };
            let out = lanes[i].tick(node, &rpc[i], "", current(i).as_deref(), key(i), now);
            for m in out {
                let WireMsg::XmrSweep(bytes) = m else { continue };
                for j in (0..4).filter(|j| *j != i) {
                    let _ = lanes[j].on_msg(&bytes, if node_of(j) == 0 { x } else { y }, now);
                }
                said.push(SweepMsg::decode(&bytes).expect("a lane's own message decodes"));
            }
        }
        said
    };

    // A DEPOSIT PAID TO THE REPLACED KEY'S ADDRESS, still a valid deposit address inside its window (R2). The watcher
    // reads the wallet the lanes keep open — the new set's — and never saw it there.
    let late = crate::bridge::xmr_integrated_address(&w1, &crate::xmr_custody::payment_id(&sid1, &[7u8; 64])).expect("an integrated address of the old key");
    assert!(crate::xmr_watch::watch_issued_reserve(&late), "the deposit address is watched");
    world.chain().fund(&late, XMR).expect("a deposit to the replaced key's address");
    world.chain().mine(crate::xmr_sim::SPEND_LOCK_BLOCKS);
    crate::xmr_watch::sweep_now(&rpc[0]).expect("the current set's wallet answers");
    assert_eq!(crate::xmr_watch::confirmed_pending_cached(&late), None, "CALIBRATION (the hole): read from the current set's wallet, a deposit to a replaced key's address is never seen");

    // A LYING PROPOSER of the old set: a sweep to another address, built and signed on its own old wallet
    let turn = (x.finalized_chain_time_ms() / crate::btc_payout::PROPOSER_SLOT_MS) as usize % 3;
    let p = (0..3).find(|i| seats[*i].id == ids1[turn]).expect("the proposer is one of the three");
    let q = (0..3).find(|i| seats[*i].id == ids1[(turn + 1) % 3]).expect("the next signer is one of the three");
    rpc[p].open_or_create(&name1, "").expect("the proposer opens the old wallet");
    let stranger = WalletRpc::from_env().expect("a stranger's wallet");
    let thief = stranger.address().expect("the stranger's address");
    let bad = rpc[p].transfer_multisig(&[(thief.clone(), 5 * XMR)]).expect("the lying proposer's wallet builds it");
    let bad = rpc[p].sign_multisig(&bad).map(|s| s.0).unwrap_or(bad);
    if let Some(name) = current(p) {
        rpc[p].open_or_create(&name, "").expect("back to the current wallet");
    }
    let lie = SweepMsg::Round { set_id: sid1, txset: bad, signers: vec![seats[p].id], txids: Vec::new(), submitted: false, signer_pk: Vec::new(), sig: Vec::new() }
        .sign(key(p))
        .expect("signed by the old set's own member");
    let qn = if node_of(q) == 0 { &x } else { &y };
    assert!(lanes[q].on_msg(&lie.encode(), qn, now), "CALIBRATION: a round signed by a member of the old set is taken in");
    now += 10_000;
    let out = lanes[q].tick(qn, &rpc[q], "", current(q).as_deref(), key(q), now);
    let signed_it = out.iter().any(|m| matches!(m, WireMsg::XmrSweep(b) if matches!(SweepMsg::decode(b), Some(SweepMsg::Round { signers, .. }) if signers.contains(&seats[q].id))));
    assert!(!signed_it && world.chain().mempool_len() == 0, "⛔ LYING PROPOSER: the next signer signed a sweep to an address its chain does not record for the vault's current key");
    assert_eq!(world.chain().received_atomic(&thief), Some(0), "⛔ the stranger was paid");
    // …and that one visit to the old key's wallet READ the deposit paid to its address
    let seen = crate::xmr_watch::confirmed_pending_cached(&late).expect("⛔ R2: a deposit paid to a replaced key's address was not read on a visit to that key's wallet — it would never be minted");
    assert_eq!(seen.0 + seen.1, XMR, "the watcher holds the deposit's whole amount (matured or still pending the daemons' agreement)");
    // a stranger to the old set
    let forged = SweepMsg::Done { set_id: sid1, txid: "ab".repeat(32), fee: 7, from: seats[3].id, signer_pk: Vec::new(), sig: Vec::new() }.sign(key(3)).expect("signed");
    assert!(!lanes[0].on_msg(&forged.encode(), &x, now), "⛔ a statement by a custodian that is not a member of the old set was kept");

    // THE HONEST SWEEP: polls until Monero holds it, then until the old members have stated it
    let mut swept: Option<(String, Vec<[u8; 32]>)> = None;
    for _ in 0..8 {
        now += 10_000;
        for m in poll(&mut lanes, &x, &y, now) {
            if let SweepMsg::Round { txids, signers, submitted: true, .. } = m {
                swept = Some((txids[0].clone(), signers));
            }
        }
        if swept.is_some() {
            break;
        }
    }
    let (txid, signers) = swept.expect("⛔ the old set did not sweep its wallet once the move was due");
    assert_eq!(signers.len(), 2, "two of the old three signed it");
    world.chain().mine(crate::xmr_sim::SPEND_LOCK_BLOCKS);
    let got = world.chain().received_atomic(&w2).expect("W2 is an address of this chain");
    let fee = 6 * XMR - got; // the 5 XMR it held and the late deposit of 1
    assert!(fee > 0 && fee < XMR, "⛔ MONERO: the current key's wallet did not receive the old wallet's coins less a fee: received {got}");
    rpc[2].open_or_create(&name1, "").expect("the leaver's old wallet");
    assert_eq!(rpc[2].balance().map(|b| b.0), Ok(0), "⛔ the replaced key's wallet still holds coins");

    // THE FEE, judged by the newcomer (custodian 3: it never held W1) on its own wallet of the current set
    y.set_custodian_identity(seats[3].id, seats[3].dk.clone());
    let evidence = XmrCostEvidence { set_id: sid1, txid: txid.clone(), fee }.encode();
    assert_eq!(lanes[3].judge_cost(&evidence, &y, &rpc[3]), None, "⛔ a cost was judged true before any member of the old set stated it");
    // the old members settle on their own old wallets and say so, one at a time
    let mut stated = 0usize;
    for i in 0..3 {
        now += 10_000;
        let node = if node_of(i) == 0 { &x } else { &y };
        let out = lanes[i].tick(node, &rpc[i], "", current(i).as_deref(), key(i), now);
        for m in out {
            let WireMsg::XmrSweep(bytes) = m else { continue };
            if matches!(SweepMsg::decode(&bytes), Some(SweepMsg::Done { .. })) {
                assert!(lanes[3].on_msg(&bytes, &y, now), "the newcomer's lane takes in an old member's statement");
                stated += 1;
            }
        }
        if stated == 1 {
            assert_eq!(lanes[3].judge_cost(&evidence, &y, &rpc[3]), None, "⛔ ONE statement of three was enough to judge the cost (two thirds of the old set must say so)");
        }
    }
    assert!(stated >= 2, "⛔ the old members did not state the sweep their own wallets show confirmed ({stated})");
    let txid32: [u8; 32] = crate::btc_tx::unhex(&txid).expect("hex").try_into().expect("32 bytes");
    assert_eq!(lanes[3].judge_cost(&evidence, &y, &rpc[3]), Some((crate::peg::XMR_PEG_ASSET_ID, fee, txid32)), "⛔ the newcomer does not derive the sweep's fee from the old set's statements and its own wallet");
    assert!(lanes[3].cost_evidence(&y).contains(&evidence), "the lane offers the cost to the cost lane");
    assert_eq!(lanes[3].fees_in_flight(&y, &rpc[3]), fee, "the unbooked fee is counted back into the solvency reading");
    assert_eq!(lanes[3].judge_cost(&XmrCostEvidence { set_id: sid1, txid: txid.clone(), fee: fee + 1 }.encode(), &y, &rpc[3]), None, "⛔ LYING PROVER: a fee one atom higher was judged true");
    assert_eq!(lanes[3].judge_cost(&XmrCostEvidence { set_id: sid1, txid: "cd".repeat(32), fee }.encode(), &y, &rpc[3]), None, "⛔ a transaction this custodian's wallet never received was judged a cost");
    // nothing more is built: the old wallet is empty
    now += 10_000;
    assert!(poll(&mut lanes, &x, &y, now).iter().all(|m| !matches!(m, SweepMsg::Round { submitted: false, .. })), "⛔ a second sweep was proposed out of an empty wallet");
    crate::xmr_watch::retire_reserve_watch(&late);
}

/// ⭐⭐ SAFE AT SCALE, stage three (spec §3f R7, R8) — COINS FIRST, THE MONERO HALF: A VAULT WHOSE MERGE IS DUE EMPTIES ITS
/// OWN CURRENT WALLET INTO THE RECEIVING VAULT'S, AND PAYS NO CASH-OUT FROM IT. Twenty-five custodians, two vaults
/// (16 + 9) on two nodes; a simulated Monero chain. Vault 1's nine members hold wallet W1 (6 of 9) with 5 XMR and the
/// chain records it as vault 1's current key; vault 0's current key records the address W0; vault 1's ledgers stand
/// moved (a deposit through the custodian doors).
///   • CONTROL, no merge due (nine members): the lanes poll with W1 open and say nothing — the wallet the custody and
///     payout lanes keep open is never swept by itself — and nobody's coins are "leaving".
///   • A member of vault 1 is slashed: eight remain, the merge 1 → 0 is due on each node's own chain.
///     `own_vault_coins_leaving` is then true for a custodian of vault 1 (both payout lanes sign and propose nothing
///     from it) and false for a custodian of vault 0.
///   • THE SWEEP: the key's holders build, sign (six of nine) and relay ONE transaction out of W1; Monero shows W0
///     holding the 5 XMR less the fee and W1 empty. Every signer read the set on its own wallet: one recipient, the
///     address its chain records for the RECEIVING vault's current key.
///   • THE FEE: a custodian of vault 1 judges it from the wallet that SENT it (its own), once two thirds of the key's
///     holders state it; before they do, a fee one atom higher, and a transaction its wallet did not send are judged
///     false. A custodian of vault 0 judges nothing: the cost is booked on the retiring vault's ledger, by its own.
/// TWO-PARTY-REVIEWED: nine custodians' lanes and wallets over two nodes; every round is signed on a lane that did not
/// build it, and the result is asserted on Monero (the simulated chain's own balances).
#[test]
fn safe_at_scale_a_due_merge_empties_the_retiring_vaults_current_monero_wallet_into_the_receiving_vaults_and_pays_no_cash_out_from_it() {
    use crate::node::objects::vault_key_tx::apply_chain_vault_key;
    use crate::protocol::WireMsg;
    use crate::vault_key_tx::{KeyApply, VaultKey, VaultKeyHeader};
    use crate::xmr_custody::{set_id, wallet_name};
    use crate::xmr_rpc::WalletRpc;
    use crate::xmr_sweep::{SweepLane, SweepMsg, XmrCostEvidence};
    const XMR: u64 = crate::xmr_rpc::XMR_ATOMIC_PER_XMR;
    let _serial = crate::xmr_sim::serial().lock().unwrap_or_else(|e| e.into_inner());
    let world = crate::xmr_sim::install(crate::xmr_sim::SimMonero::new(0x5eed_2026_1112));
    let (mut x, mut y) = (testnet_node(), testnet_node());
    let seats = seat_all(&mut [&mut x, &mut y], 25);
    let vaults = x.custody_vaults();
    let of = |v: usize| -> Vec<&Seat> { seats.iter().filter(|s| vaults[v].contains(&s.id)).collect() };
    let (v0, v1_all) = (of(0), of(1));
    assert_eq!((v0.len(), v1_all.len()), (16, 9), "PRECONDITION: two vaults, sixteen and nine");
    let verifier = crate::pqauth::MlDsaVerifier;
    // a key statement of `vault`'s members with their Monero address, applied on both nodes
    let take = |x: &mut Node, y: &mut Node, vault: u32, members: &[&Seat], address: &str, blue: u64| {
        let mut ids: Vec<[u8; 32]> = members.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        let msg = x.peg().vault_key_take_msg(vault, &x.vault_btc_key(vault), &ids, address.as_bytes());
        let key = VaultKey { header: VaultKeyHeader::Take { vault, members: ids, xmr_address: address.as_bytes().to_vec() }, attestors: sign(members, &msg) };
        for n in [x, y] {
            assert!(matches!(apply_chain_vault_key(n, &key.wire(), Some(blue), &verifier), KeyApply::Taken), "vault {vault}'s members take the key of their set");
        }
    };
    // vault 0's wallet is the receiving one: only its recorded address matters here
    let w0_rpc = WalletRpc::from_env().expect("the simulated Monero answers");
    let w0 = w0_rpc.address().expect("the receiving vault's address");
    take(&mut x, &mut y, 0, &v0, &w0, 0);
    // vault 1's nine members hold W1 (six of nine), and the chain records it as vault 1's current key
    let v1 = v1_all;
    let mut ids1: Vec<[u8; 32]> = v1.iter().map(|s| s.id).collect();
    ids1.sort_unstable();
    let (sid1, name1) = (set_id(&ids1), wallet_name(&set_id(&ids1)));
    let rpc: Vec<WalletRpc> = (0..9).map(|_| WalletRpc::from_env().expect("the simulated Monero answers")).collect();
    for w in &rpc {
        w.open_or_create(&name1, "").expect("vault 1's wallet");
    }
    let w1 = xmr_form(&rpc.iter().collect::<Vec<_>>());
    take(&mut x, &mut y, 1, &v1, &w1, 0);
    world.chain().fund(&w1, 5 * XMR).expect("vault 1's Monero");
    world.chain().mine(crate::xmr_sim::SPEND_LOCK_BLOCKS);
    // vault 1's ledgers stand moved (a deposit through the custodian doors)
    x.set_custodian_identity(v1[0].id, v1[0].dk.clone());
    let _dep = vault_deposit(&mut x, &mut y, &mut [], &v1, 1, 3_000, 2_000, 1_000, 1);
    y.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    // every holder of the key runs its lane with W1 open — the slashed member too: a key holder the chain no longer
    // seats still runs the sweep lane, and the proposer's turn may be its own
    let key = |i: usize| Some((v1[i].pk.as_slice(), v1[i].sk.as_slice()));
    let node_of = |i: usize| i % 2; // members on X and Y alternately
    let mut lanes: Vec<SweepLane> = (0..9).map(|_| SweepLane::new()).collect();
    let poll = |lanes: &mut Vec<SweepLane>, x: &Node, y: &Node, now: u64| -> Vec<SweepMsg> {
        let mut said = Vec::new();
        for i in 0..9 {
            let node = if node_of(i) == 0 { x } else { y };
            let out = lanes[i].tick(node, &rpc[i], "", Some(name1.as_str()), key(i), now);
            for m in out {
                let WireMsg::XmrSweep(bytes) = m else { continue };
                for j in (0..9).filter(|j| *j != i) {
                    let _ = lanes[j].on_msg(&bytes, if node_of(j) == 0 { x } else { y }, now);
                }
                said.push(SweepMsg::decode(&bytes).expect("a lane's own message decodes"));
            }
        }
        said
    };
    let mut now = 10_000u64;

    // CONTROL: nine seated, ledgers moved, NO merge due — the wallet the lanes keep open is never swept by itself
    assert_eq!(x.vault_merge_due(), None, "CALIBRATION: nine members is above half strength — no merge is due yet");
    assert!(!x.own_vault_coins_leaving() && !y.own_vault_coins_leaving(), "CALIBRATION: with no merge due nobody's coins are leaving");
    for _ in 0..3 {
        now += 10_000;
        assert!(poll(&mut lanes, &x, &y, now).is_empty(), "⛔ with no merge due a lane visited or swept the wallet the custody and payout lanes keep open");
    }
    assert_eq!(world.chain().mempool_len(), 0, "⛔ a sweep of the open wallet reached Monero with no merge due");
    // A member of vault 1 is slashed: eight remain, at half strength, with moved ledgers — the merge is due
    for n in [&mut x, &mut y] {
        assert!(n.apply_slash(v1[8].id).is_some(), "the slash takes the ninth seat");
    }
    assert_eq!(x.vault_merge_due(), Some((1, 0)), "PRECONDITION: vault 1's merge into vault 0 is due on each node's own chain");
    assert!(x.own_vault_coins_leaving(), "⛔ a custodian of the retiring vault does not read its own coins as leaving: both payout lanes would pay cash-outs from a wallet being emptied");
    assert!(!y.own_vault_coins_leaving(), "⛔ a custodian of the RECEIVING vault reads its coins as leaving: it would pay nothing");

    // THE SWEEP: polls until Monero holds it
    let mut swept: Option<(String, Vec<[u8; 32]>)> = None;
    for _ in 0..24 {
        now += 10_000;
        for m in poll(&mut lanes, &x, &y, now) {
            if let SweepMsg::Round { txids, signers, submitted: true, .. } = m {
                swept = Some((txids[0].clone(), signers));
            }
        }
        if swept.is_some() {
            break;
        }
    }
    let (txid, signers) = swept.expect("⛔ R7: the retiring vault did not move its current wallet's Monero to the receiving vault once its merge was due");
    assert_eq!(signers.len(), 6, "six of the key's nine holders signed it");
    world.chain().mine(crate::xmr_sim::SPEND_LOCK_BLOCKS);
    let got = world.chain().received_atomic(&w0).expect("W0 is an address of this chain");
    let fee = 5 * XMR - got;
    assert!(fee > 0 && fee < XMR, "⛔ MONERO: the receiving vault's wallet did not receive the retiring vault's coins less a fee: received {got}");
    assert_eq!(rpc[0].balance().map(|b| b.0), Ok(0), "⛔ the retiring vault's wallet still holds coins");

    // THE FEE, judged by a custodian of the retiring vault from the wallet that SENT it
    let evidence = XmrCostEvidence { set_id: sid1, txid: txid.clone(), fee }.encode();
    assert_eq!(lanes[0].judge_cost(&evidence, &x, &rpc[0]), None, "⛔ a cost was judged true before the set stated it");
    let mut stated = 0usize;
    for _ in 0..4 {
        now += 10_000;
        stated += poll(&mut lanes, &x, &y, now).iter().filter(|m| matches!(m, SweepMsg::Done { .. })).count();
    }
    assert!(stated >= 6, "⛔ the members did not state the sweep their own wallets show confirmed ({stated})");
    let txid32: [u8; 32] = crate::btc_tx::unhex(&txid).expect("hex").try_into().expect("32 bytes");
    assert_eq!(lanes[0].judge_cost(&evidence, &x, &rpc[0]), Some((crate::peg::XMR_PEG_ASSET_ID, fee, txid32)), "⛔ a custodian of the retiring vault does not derive the merge sweep's fee from the wallet that sent it");
    assert_eq!(lanes[0].judge_cost(&XmrCostEvidence { set_id: sid1, txid: txid.clone(), fee: fee + 1 }.encode(), &x, &rpc[0]), None, "⛔ LYING PROVER: a fee one atom higher was judged true");
    assert_eq!(lanes[0].judge_cost(&XmrCostEvidence { set_id: sid1, txid: "cd".repeat(32), fee }.encode(), &x, &rpc[0]), None, "⛔ a transaction this custodian's wallet never sent was judged a cost");
    // a custodian of the RECEIVING vault judges nothing of it: the cost is the retiring vault's own
    assert_eq!(lanes[1].judge_cost(&evidence, &y, &w0_rpc), None, "⛔ a custodian of another vault judged the retiring vault's cost");
    // nothing more is built: the wallet is empty
    now += 10_000;
    assert!(poll(&mut lanes, &x, &y, now).iter().all(|m| !matches!(m, SweepMsg::Round { submitted: false, .. })), "⛔ a second sweep was proposed out of an empty wallet");
}

/// ⭐⭐ SAFE AT SCALE, stage three (finding A-F21; spec §3f R6) — A FEE THAT LEFT CUSTODY IS BOOKED BY THE VAULT'S OWN
/// CUSTODIANS, EACH FROM ITS OWN OPENING, AND BECOMES THE BONDERS' DEBT ON EVERY NODE. Nine custodians are one vault
/// with a deposit behind it. Nodes: A (custodian 0, who frames), B (signs as five more, one after the other) and C
/// (no seat: it gathers signatures and takes the object from A's block).
///   • every custodian derives the SAME header from its own opening (the reserve after, under the blind each derives);
///   • a stranger's signature and a signature over another reserve-after count for nothing toward it;
///   • five of nine do not frame; the sixth does, and the framer's own opening proves the fall;
///   • C holds the vault's reserve on the stated commitment and the bonders' debt raised by the fee at the chain's
///     own price — the same words on every node; a booked cost is signed by nobody again;
///   • the debt is then paid by the bonders' share of fees alone (`PegLedger::credit_fee_pools_capped`, pinned at the
///     ledger in `peg::tests`).
/// TWO-PARTY-REVIEWED: the signers are on A and B, the framer is A, and every result is asserted on C, which holds
/// no seat and only folded A's block.
#[test]
fn safe_at_scale_a_fee_that_left_custody_is_booked_by_the_vaults_own_custodians_and_becomes_the_bonders_debt_on_the_peer() {
    use crate::reserve_cost_tx::{ReserveCost, ReserveCostSig};
    let (mut a, mut b, mut c) = (testnet_node(), testnet_node(), testnet_node());
    let seats = seat_all(&mut [&mut a, &mut b, &mut c], 9);
    let v0: Vec<&Seat> = seats.iter().collect();
    a.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    let btc = crate::peg::NATIVE_PEG_ASSET_ID;
    let _dep = vault_deposit(&mut a, &mut b, &mut [&mut c], &v0, 0, 3_000, 2_000, 1_000, 1);
    let ledger = a.ledger_here(btc);
    let verifier = crate::pqauth::MlDsaVerifier;
    let (txid, fee, evidence) = ([0x7eu8; 32], 300u64, b"the move, re-judged by every signer on its own source".to_vec());
    let before = pair(&c, 0, btc);
    assert_eq!(c.peg().custody_cost_debt(), (0, 0), "PRECONDITION: the bonders owe nothing");

    // each custodian signs the header ITS OWN opening derives
    let mut sigs: Vec<ReserveCostSig> = vec![a.own_reserve_cost_sig(&v0[0].pk, &v0[0].sk, btc, fee, &txid, &evidence).expect("custodian 0 signs from its opening")];
    for m in &v0[1..6] {
        b.set_custodian_identity(m.id, m.dk.clone());
        sigs.push(b.own_reserve_cost_sig(&m.pk, &m.sk, btc, fee, &txid, &evidence).expect("a custodian of the vault signs from its opening"));
    }
    let header = sigs[0].header;
    assert!(sigs.iter().all(|s| s.header == header), "⛔ two custodians of one vault derived different headers for one cost");
    assert!(a.own_reserve_cost_sig(&v0[6].pk, &v0[6].sk, btc, fee, &txid, &evidence).is_none(), "⛔ a node signed as a custodian it is not");

    // what does NOT count
    let stranger = seat(77);
    let msg = a.peg().reserve_cost_msg(header.ledger, header.cost, &header.txid, &header.post_reserve);
    let forged = ReserveCostSig { header, evidence: evidence.clone(), pubkey: stranger.pk.clone(), sig: crate::pqauth::ml_dsa_sign(&msg, &stranger.sk).expect("signs") };
    assert!(!a.reserve_cost_sig_ingest(&forged, &verifier) && !c.reserve_cost_sig_ingest(&forged, &verifier), "⛔ a signature by nobody the chain seats in the vault was gathered");
    let lifted = ReserveCostSig { header: crate::reserve_cost_tx::ReserveCostHeader { cost: fee + 1, ..header }, ..sigs[1].clone() };
    assert!(!a.reserve_cost_sig_ingest(&lifted, &verifier), "⛔ a signature was counted for a header it does not sign");

    // five of nine do not frame; six do — gathered through the wire encoding, on the framer and on the relay
    for s in &sigs[..5] {
        let s = ReserveCostSig::decode(&s.wire()).expect("the signature decodes");
        assert!(a.reserve_cost_sig_ingest(&s, &verifier) && c.reserve_cost_sig_ingest(&s, &verifier), "a custodian's signature is gathered on the framer and on a node with no seat");
        assert!(!a.reserve_cost_sig_ingest(&s, &verifier), "a repeat is not new (not relayed again)");
    }
    assert!(a.reserve_cost_ready_to_frame(&verifier).is_none(), "⛔ five of nine framed a cost");
    // a custodian that signs ANOTHER reserve-after gathers apart and never completes the honest header
    let other = crate::reserve_cost_tx::ReserveCostHeader { post_reserve: before.0, ..header };
    let other_msg = a.peg().reserve_cost_msg(other.ledger, other.cost, &other.txid, &other.post_reserve);
    let lying = ReserveCostSig { header: other, evidence: evidence.clone(), pubkey: v0[5].pk.clone(), sig: crate::pqauth::ml_dsa_sign(&other_msg, &v0[5].sk).expect("signs") };
    assert!(a.reserve_cost_sig_ingest(&lying, &verifier), "CALIBRATION: a seated custodian's own statement is gathered — under its own header");
    assert!(a.reserve_cost_ready_to_frame(&verifier).is_none(), "⛔ a signature over another reserve-after completed the honest header");
    assert!(a.reserve_cost_sig_ingest(&sigs[5], &verifier));
    let (h, atts, open) = a.reserve_cost_ready_to_frame(&verifier).expect("six of nine: the framer holds two thirds of its vault for the header its own opening derives");
    assert_eq!(h, header);
    let (post, sum, bound, _) = crate::peg::PegLedger::prove_reserve_cost_from(h.ledger, open, h.cost, &h.txid).expect("the framer's opening proves the fall");
    assert_eq!(post, header.post_reserve, "the proof's commitment is the header's");
    let cost = ReserveCost { header: h, sum, bound, attestors: atts };
    assert!(a.publish_reserve_cost(&cost).is_ok());
    let blk = a.produce(60_000, Hash32::hash(b"cost-lane"), Hash32::hash(b"vault-mc")).expect("the block with the cost");
    for n in [&mut b, &mut c] {
        n.ingest_block(blk.clone(), 60_400);
    }
    let _ = a.fold_past_blocks_for_test(&mut [&mut b, &mut c], 60_000, 50, b"cost-lane-fold");

    // ON THE PEER
    assert_eq!(pair(&c, 0, btc), (header.post_reserve, before.1), "⛔ the PEER does not hold the vault's reserve on the booked commitment");
    let price = c.peg().twap7(btc).expect("the chain prices Bitcoin");
    let owed = u64::try_from(u128::from(fee) * price / crate::liquidation::PRICE_SCALE).expect("fits");
    assert!(owed > 0, "PRECONDITION: the fee has a price");
    for (n, name) in [(&a, "A"), (&b, "B"), (&c, "the peer")] {
        assert_eq!(n.peg().custody_cost_debt(), (owed, 0), "⛔ {name}: the booked fee is not the bonders' debt at the chain's own price");
        assert!(n.reserve_cost_booked(ledger, &txid), "{name} holds the cost's one-time id spent");
    }
    assert!(a.own_reserve_cost_sig(&v0[0].pk, &v0[0].sk, btc, fee, &txid, &evidence).is_none(), "⛔ a booked cost was signed again");
    assert!(a.reserve_cost_ready_to_frame(&verifier).is_none() && a.reserve_costs_unsigned(&v0[0].pk).is_empty(), "the lane holds nothing for a booked cost");
}

/// ⭐⭐ SAFE AT SCALE, stage three (spec §3f R5, §3f.2) — THE WEEKLY ROTATION IS A FOLD RULE EVERY NODE DERIVES: two
/// custodians of a due vault change places with two of a drawn partner, nobody proposes or signs it, and what follows is
/// what follows any member change. Two nodes (A produces; C only follows), 25 custodians in two vaults (16 and 9), a
/// 21-block unbonding window (so a rotation period is 7 blue and a rotation day 1):
///   • CALIBRATION: with no key recorded no vault is settled — blocks fold and nobody moves;
///   • both vaults take their keys; at the first fold step vault 1's own day has come, on BOTH nodes the same two
///     custodians of each vault have changed places (sizes 16 and 9 unchanged), both vaults are marked mixed at that
///     step's blue score, and each vault's node says it owes a key that names its seats;
///   • nothing mixes again while a vault's key is not its members', nor — after both take their new keys and a whole
///     period has passed — while a replaced key is still alive (the vault STAYS DUE);
///   • THE BONDERS' DEBT HOLDS IT TOO: the replaced keys are retired with a sweep's cost still owed — nothing mixes;
///   • the debt is paid from the bonders' own share: at the next fold step the vaults mix again, the longest-waiting
///     (lowest index among equals) initiating;
///   • REWIND: taking that step back restores every custodian's seat and both vaults' words on A, and folding it again
///     gives the peer's seats — the mix is a function of the chain, not of when a node folded.
/// TWO-PARTY-REVIEWED: every key object is applied on C from its bytes and every seat is asserted on C; A is compared.
#[test]
fn safe_at_scale_a_due_vault_mixes_two_custodians_with_a_drawn_partner_on_every_node_and_stays_due_until_it_can() {
    use crate::node::objects::vault_key_tx::apply_chain_vault_key;
    use crate::vault_key_tx::{KeyApply, VaultKey, VaultKeyHeader};
    let (mut a, mut c) = (dd_node(), dd_node());
    for n in [&mut a, &mut c] {
        let mut gp = n.params().clone();
        gp.governance_set_stake_lock_blocks(0);
        gp.merge_depth_cap = 4;
        gp.governance_set_unbonding_blocks(21);
        n.set_params(gp);
    }
    let seats = seat_all(&mut [&mut a, &mut c], 25);
    assert_eq!((a.vault_rotation_period_ticks(), a.vault_key_window_ticks()), (7, 1), "PRECONDITION: a period of seven blue, a day of one");
    let verifier = crate::pqauth::MlDsaVerifier;
    let members = |n: &Node, v: usize| -> Vec<[u8; 32]> { n.custody_vaults()[v].clone() };
    let seated = |n: &Node, v: usize| -> Vec<&Seat> { seats.iter().filter(|s| members(n, v).contains(&s.id)).collect() };
    let seat_map = |n: &Node| n.validators().custody_seats();
    let tick = |n: &Node| n.chain_tick(); // A-F60: the custody record's clock
    // one block of A's, grafted by C, folded on both
    let carry = |a: &mut Node, c: &mut Node, ts: u64, tag: &[u8]| -> u64 {
        let blk = a.produce(ts, Hash32::hash(tag), Hash32::hash(b"rotation-mc")).expect("A produces");
        let _ = c.ingest_block(blk, ts + 400);
        a.fold_past_for_test(&mut [c], ts + 400, tag)
    };
    // the seated members of vault `v` take the key of their set, the same object applied on both nodes
    let take = |a: &mut Node, c: &mut Node, v: u32| {
        let ids = members(c, v as usize);
        let signers: Vec<&Seat> = seats.iter().filter(|s| ids.contains(&s.id)).collect();
        let msg = c.peg().vault_key_take_msg(v, &c.vault_btc_key(v), &ids, b"");
        let key = VaultKey { header: VaultKeyHeader::Take { vault: v, members: ids, xmr_address: Vec::new() }, attestors: sign(&signers, &msg) };
        let at = c.chain_tick();
        for n in [a, c] {
            assert!(matches!(apply_chain_vault_key(n, &key.wire(), Some(at), &verifier), KeyApply::Taken), "vault {v}'s members take the key of their set");
        }
    };
    let retire = |a: &mut Node, c: &mut Node, v: u32| {
        let old = c.peg().vault_keys(v).first().expect("a replaced key").since_tick;
        let ids = members(c, v as usize);
        let signers: Vec<&Seat> = seats.iter().filter(|s| ids.contains(&s.id)).collect();
        let key = VaultKey { header: VaultKeyHeader::Retire { vault: v, since_tick: old }, attestors: sign(&signers, &c.peg().vault_key_retire_msg(v, old)) };
        let at = c.chain_tick();
        for n in [a, c] {
            assert!(matches!(apply_chain_vault_key(n, &key.wire(), Some(at), &verifier), KeyApply::Retired), "vault {v}'s members retire their replaced key");
        }
    };
    let sizes = |n: &Node| n.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>();
    assert_eq!(sizes(&c), vec![16, 9]);
    let seats_0 = seat_map(&c);

    // A-F60: the rotation period (7) and day (1) are TICKS of the chain's own clock (median time past), never block counts —
    // custodians re-key weekly, a time. Advance the clock a tick at a time (one target spacing of chain time per carry); every
    // loop below stops on the MEASURED tick, so the real block rate and the block count never enter.
    let step = crate::dag::MESH_TARGET_SPACING_MS;
    let mut carries = 0u32;
    let mut adv = |a: &mut Node, c: &mut Node, ts: &mut u64, target: u64, tag: &[u8], cap: &mut u32| {
        while c.chain_tick() < target {
            *ts = carry(a, c, *ts, tag);
            *ts += step;
            *cap += 1;
            assert!(*cap < 400, "⛔ the chain's clock did not reach tick {target} (at {}) — the fixture is not advancing time", c.chain_tick());
        }
    };
    // CALIBRATION: no key recorded, so no vault is settled
    let mut ts = 5_000u64;
    adv(&mut a, &mut c, &mut ts, 1, b"rot-calib", &mut carries);
    assert!(tick(&c) >= 1, "PRECONDITION: vault 1's own day (one tick of the chain's clock) has come");
    assert_eq!(seat_map(&c), seats_0, "CALIBRATION: a vault with no key recorded mixes nobody");
    assert_eq!((c.peg().vault_mixed_tick(0), c.peg().vault_mixed_tick(1)), (0, 0));

    // BOTH TAKE THEIR KEYS; the next fold step mixes them
    take(&mut a, &mut c, 0);
    take(&mut a, &mut c, 1);
    {
        let mut cap = 0u32;
        while c.peg().vault_mixed_tick(1) == 0 {
            ts = carry(&mut a, &mut c, ts + step, b"rot-first");
            cap += 1;
            assert!(cap < 400, "⛔ the settled, due pair never mixed as the chain's clock advanced");
        }
    }
    let seats_1 = seat_map(&c);
    assert_eq!(seat_map(&a), seats_1, "⛔ the two nodes hold different seats after the same fold step");
    let moved: Vec<[u8; 32]> = seats_0.iter().zip(seats_1.iter()).filter(|(x, y)| x.1 != y.1).map(|(x, _)| x.0).collect();
    assert_eq!(seats_0.iter().map(|(id, _)| *id).collect::<Vec<_>>(), seats_1.iter().map(|(id, _)| *id).collect::<Vec<_>>(), "the same custodians are seated");
    let was_in = |id: &[u8; 32], v: usize| seats_0.iter().any(|(i, s)| i == id && crate::custody_vaults::vault_of_seat(*s) == v);
    eprintln!(
        "[vault-rotation] first mix: {} custodian(s) changed seats ({} from vault 0, {} from vault 1); vaults now {:?}; mixed at blue {} and {}",
        moved.len(),
        moved.iter().filter(|id| was_in(id, 0)).count(),
        moved.iter().filter(|id| was_in(id, 1)).count(),
        sizes(&c),
        c.peg().vault_mixed_tick(0),
        c.peg().vault_mixed_tick(1)
    );
    assert_eq!(moved.len(), 2 * crate::custody_vaults::MIX, "⛔ a rotation moves two custodians of each vault, on the peer");
    assert_eq!(moved.iter().filter(|id| was_in(id, 0)).count(), crate::custody_vaults::MIX, "two of them sat in vault 0");
    for id in &moved {
        let now_in = seats_1.iter().find(|(i, _)| i == id).map(|(_, s)| crate::custody_vaults::vault_of_seat(*s)).expect("seated");
        assert_ne!(was_in(id, 0), now_in == 0, "⛔ a moved custodian did not change vaults");
    }
    assert_eq!(sizes(&c), vec![16, 9], "⛔ a rotation changed a vault's size");
    let mixed_1 = c.peg().vault_mixed_tick(0);
    assert!(mixed_1 >= 1 && c.peg().vault_mixed_tick(1) == mixed_1, "both vaults are marked mixed at the same step");
    assert_eq!((a.peg().vault_mixed_tick(0), a.peg().vault_mixed_tick(1)), (mixed_1, mixed_1), "…on both nodes");
    // each vault's key now names two custodians seated elsewhere: its take is due at once, from its own node's chain
    for v in 0..2usize {
        let (stayer_id, stayer_dk) = {
            let s = seated(&c, v).into_iter().find(|s| !moved.contains(&s.id)).expect("a custodian that stayed");
            (s.id, s.dk.clone())
        };
        c.set_custodian_identity(stayer_id, stayer_dk);
        assert_eq!(
            c.vault_key_take_due(false, None),
            Some(VaultKeyHeader::Take { vault: v as u32, members: members(&c, v), xmr_address: Vec::new() }),
            "⛔ vault {v} does not owe the key of its new seats after the mix"
        );
    }

    // NOTHING MIXES AGAIN while a key is not its members', nor while a replaced key is alive — even a period later
    let period = a.vault_rotation_period_ticks();
    adv(&mut a, &mut c, &mut ts, mixed_1 + period, b"rot-unsettled", &mut carries);
    assert_eq!(seat_map(&c), seats_1, "⛔ a vault whose key is not its members' mixed again");
    take(&mut a, &mut c, 0);
    take(&mut a, &mut c, 1);
    assert_eq!((c.peg().vault_mixed_tick(0), c.peg().vault_mixed_tick(1)), (mixed_1, mixed_1), "⛔ a take did not carry the vault's last mix forward");
    adv(&mut a, &mut c, &mut ts, mixed_1 + period + 1, b"rot-period", &mut carries);
    assert_eq!(seat_map(&c), seats_1, "⛔ a vault with a replaced key still alive mixed (its last re-key's coins are not home)");

    // THE DEBT HOLDS IT TOO: the replaced keys retire while the bonders still owe a sweep's cost
    for n in [&mut a, &mut c] {
        n.peg.set_price_mark_for_test(crate::peg::NATIVE_PEG_ASSET_ID, 2 * crate::liquidation::PRICE_SCALE, 1);
        assert_eq!(n.peg.raise_custody_cost_debt(crate::peg::NATIVE_PEG_ASSET_ID, 500), 1_000, "PRECONDITION: a booked sweep cost is the bonders' debt");
    }
    // A-F60: a replaced key retires only once its address window (a TIME) has passed. Advance the chain's own clock past
    // the latest replaced key's window, read from the record — so the margin never rides on the block rate. The vaults stay
    // unsettled (a replaced key alive) and the debt is set, so nothing mixes while the clock moves.
    {
        let win = a.vault_key_window_ticks();
        let need = c.peg().vault_keys(0).iter().chain(c.peg().vault_keys(1).iter()).filter_map(|k| k.replaced_tick).max().unwrap_or(0) + win + 1;
        adv(&mut a, &mut c, &mut ts, need, b"rot-retire-window", &mut carries);
    }
    retire(&mut a, &mut c, 0);
    retire(&mut a, &mut c, 1);
    assert!(c.peg().vault_keys(0).len() == 1 && c.peg().vault_keys(1).len() == 1, "PRECONDITION: both vaults hold their current key alone");
    { let d = c.chain_tick() + 1; adv(&mut a, &mut c, &mut ts, d, b"rot-debt", &mut carries); }
    assert_eq!(seat_map(&c), seats_1, "⛔ the vaults mixed while the bonders still owe for earlier sweeps");
    // …and paid from the bonders' own share (a quarter of each fee): the next fold step mixes
    for n in [&mut a, &mut c] {
        assert!(n.peg.credit_fee_pools_capped(4_000, 0, u64::MAX));
        assert_eq!(n.peg().custody_cost_debt().0, 0, "PRECONDITION: the debt is paid");
    }
    let before_second = (a.selected_tip().expect("a tip"), seat_map(&a));
    { let d = c.chain_tick() + 1; adv(&mut a, &mut c, &mut ts, d, b"rot-second", &mut carries); }
    let seats_2 = seat_map(&c);
    assert_ne!(seats_2, seats_1, "⛔ a due, settled pair with no debt did not mix");
    assert_eq!(seat_map(&a), seats_2, "⛔ the two nodes hold different seats after the second mix");
    assert_eq!(seats_1.iter().zip(seats_2.iter()).filter(|(x, y)| x.1 != y.1).count(), 2 * crate::custody_vaults::MIX);
    assert_eq!(sizes(&c), vec![16, 9]);
    let mixed_2 = c.peg().vault_mixed_tick(0);
    assert!(mixed_2 >= mixed_1 + a.vault_rotation_period_ticks() && c.peg().vault_mixed_tick(1) == mixed_2, "both words moved to the second mix's step");

    // REWIND: the step taken back restores seats and words; folded again it gives the peer's
    a.rewind_fold_to_common(before_second.0);
    assert_eq!(seat_map(&a), before_second.1, "⛔ a rewound mix left custodians on the seats it gave them");
    assert_eq!((a.peg().vault_mixed_tick(0), a.peg().vault_mixed_tick(1)), (mixed_1, mixed_1), "⛔ a rewound mix left its vaults marked");
    let _ = a.fold_canonical_records();
    assert_eq!(seat_map(&a), seats_2, "⛔ the same step folded again gave other seats than the peer holds");
    assert_eq!((a.peg().vault_mixed_tick(0), a.peg().vault_mixed_tick(1)), (mixed_2, mixed_2));
    let _ = ts;
}

/// ⭐⭐ SAFE AT SCALE (R5 at ten vaults; spec §3f.2) — 160 CUSTODIANS, TEN FULL VAULTS, A PERIOD AND A DAY OF CHAIN TIME ON
/// TWO NODES. The claim at this size, asserted on the peer: on no rotation day are more than `2·⌈10/7⌉ = 4` vaults
/// marked mixed (two pairs); every vault mixes within its first period and a day; no vault is ever marked twice
/// within half a period (a partner is rested); every vault still holds sixteen custodians; and both nodes hold the
/// same seats and the same words at the end. The test plays the custodians' part as their lanes would: a mixed vault
/// takes the key of its new seats, and retires the replaced key once its address window has passed.
/// A 168-block unbonding window: a rotation period of 56 blue, a rotation day (and address window) of 8.
/// TWO-PARTY-REVIEWED: every key object is applied on C from its bytes and every figure is read on C; A is compared.
#[test]
fn safe_at_scale_ten_vaults_rotate_inside_the_days_bound_and_every_vault_mixes_within_a_period_on_both_nodes() {
    use crate::node::objects::vault_key_tx::apply_chain_vault_key;
    use crate::vault_key_tx::{KeyApply, VaultKey, VaultKeyHeader};
    const VAULTS: u32 = 10;
    let (mut a, mut c) = (dd_node(), dd_node());
    for n in [&mut a, &mut c] {
        let mut gp = n.params().clone();
        gp.governance_set_stake_lock_blocks(0);
        gp.merge_depth_cap = 4;
        gp.governance_set_unbonding_blocks(168);
        n.set_params(gp);
    }
    let seats = seat_all(&mut [&mut a, &mut c], 160);
    let (period, day) = (a.vault_rotation_period_ticks(), a.vault_key_window_ticks());
    assert_eq!((period, day), (56, 8), "PRECONDITION: a period of 56 blue, a day of 8");
    let verifier = crate::pqauth::MlDsaVerifier;
    let sizes = |n: &Node| n.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>();
    assert_eq!(sizes(&c), vec![16; VAULTS as usize]);
    let tick = |n: &Node| n.chain_tick(); // A-F60: the custody record's clock
    let words = |n: &Node| (0..VAULTS).map(|v| n.peg().vault_mixed_tick(v)).collect::<Vec<u64>>();
    // the custodians' part: one key object signed by a vault's seated members, applied on both nodes
    let apply = |a: &mut Node, c: &mut Node, header: VaultKeyHeader, msg: Vec<u8>, v: u32, want_take: bool| {
        let ids = c.custody_vaults()[v as usize].clone();
        let signers: Vec<&Seat> = seats.iter().filter(|s| ids.contains(&s.id)).collect();
        let key = VaultKey { header, attestors: sign(&signers, &msg) };
        let at = c.chain_tick();
        for n in [a, c] {
            let did = apply_chain_vault_key(n, &key.wire(), Some(at), &verifier);
            assert!(if want_take { matches!(did, KeyApply::Taken) } else { matches!(did, KeyApply::Retired) }, "vault {v}'s members' key statement applies: {did:?}");
        }
    };
    let settle = |a: &mut Node, c: &mut Node| {
        for v in 0..VAULTS {
            let rows = c.peg().vault_keys(v).to_vec();
            let ids = c.custody_vaults()[v as usize].clone();
            if rows.last().is_none_or(|k| k.members != ids) {
                let msg = c.peg().vault_key_take_msg(v, &c.vault_btc_key(v), &ids, b"");
                apply(&mut *a, &mut *c, VaultKeyHeader::Take { vault: v, members: ids, xmr_address: Vec::new() }, msg, v, true);
            } else if rows.len() == 2 && rows[0].replaced_tick.is_some_and(|r| c.chain_tick() >= r + day) {
                let msg = c.peg().vault_key_retire_msg(v, rows[0].since_tick);
                apply(&mut *a, &mut *c, VaultKeyHeader::Retire { vault: v, since_tick: rows[0].since_tick }, msg, v, false);
            }
        }
    };
    settle(&mut a, &mut c);
    assert!((0..VAULTS).all(|v| c.peg().vault_keys(v).len() == 1), "PRECONDITION: every vault holds its key");

    let mut ts = 5_000u64;
    let mut marks: Vec<(u32, u64)> = Vec::new(); // (vault, the blue score it was marked at), in order
    let mut held = words(&c);
    let mut round = 0u64;
    while tick(&c) < period + 2 * day {
        // A-F60: advance the chain's own clock ~one tick (one target spacing of chain time) per round; the loop above stops on
        // the MEASURED tick, so the block count and the real rate never enter.
        let blk = a.produce(ts, Hash32::hash(&round.to_le_bytes()), Hash32::hash(b"rotation-scale-mc")).expect("A produces");
        let _ = c.ingest_block(blk, ts + 400);
        ts = a.fold_past_for_test(&mut [&mut c], ts + 400, &round.to_le_bytes()) + crate::dag::MESH_TARGET_SPACING_MS;
        round += 1;
        let now = words(&c);
        for v in 0..VAULTS as usize {
            if now[v] != held[v] {
                marks.push((v as u32, now[v]));
            }
        }
        held = now;
        assert_eq!(sizes(&c), vec![16; VAULTS as usize], "⛔ a rotation changed a vault's size");
        settle(&mut a, &mut c);
    }
    let bound = 2 * (VAULTS as usize).div_ceil(crate::custody_vaults::ROTATION_DAYS as usize);
    let mut per_day: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
    for (_, at) in &marks {
        *per_day.entry(at / day).or_default() += 1;
    }
    let never: Vec<u32> = (0..VAULTS).filter(|v| held[*v as usize] == 0).collect();
    eprintln!(
        "[vault-rotation] {VAULTS} vaults over {} blue ({round} rounds): {} marks, vaults marked per rotation day {:?} (the bound is {bound}); never mixed: {never:?}",
        tick(&c),
        marks.len(),
        per_day.values().collect::<Vec<_>>()
    );
    assert!(per_day.values().all(|n| *n <= bound), "⛔ more than {bound} vaults were marked mixed on one rotation day: {per_day:?}");
    assert!(never.is_empty(), "⛔ a period and two days passed and vault(s) {never:?} never mixed");
    for v in 0..VAULTS {
        let mine: Vec<u64> = marks.iter().filter(|(m, _)| *m == v).map(|(_, at)| *at).collect();
        assert!(mine.windows(2).all(|w| w[1] >= w[0] + period / 2), "⛔ vault {v} was marked twice within half a period: {mine:?}");
    }
    assert_eq!(a.validators().custody_seats(), c.validators().custody_seats(), "⛔ the two nodes hold different seats");
    assert_eq!(words(&a), words(&c), "⛔ the two nodes hold different last-mix words");
    assert_eq!(c.validators().custody_seats().len(), seats.len(), "every custodian is still seated");
}

/// ⭐⭐ SAFE AT SCALE, stage three (spec §3f R4b) — NOBODY IS HELD HOSTAGE BY THE RELEASE GATE. Two nodes on the real
/// path (A publishes and produces, B is fed A's blocks alone; every figure is read on B and A is compared). Two
/// custodians: V (50,000, who leaves) and W (150,000, who stays), a six-key quarter, the vault's ledgers moved.
///   • HELD: V and W take the key of their set; V unbonds; its window passes; the gate still holds its collateral
///     (the key names it and coins may sit under it). The bonders are credited a fee; at the fold step that closes
///     the quarter, on BOTH nodes, W's claimable own yield has not moved and V's has risen by exactly W's own-weight
///     yield of the quarter. The pool's entitlements did not rise.
///   • REWIND: A takes the closing step back — W's accrual and V's are where they stood and the index is the old one;
///     folded again, A holds what B holds.
///   • CALIBRATION, the same chain with NO key record (the gate holds nobody, V's collateral returns at its window):
///     at the close W earns its quarter and V is credited nothing.
/// TWO-PARTY-REVIEWED: the key object is applied on B from its bytes; the unbond and every block reach B only as A
/// laid them; the diversion itself is carried by nobody — each node's own fold derives it.
#[test]
fn safe_at_scale_a_vault_that_holds_a_leaver_past_its_window_pays_it_the_quarter_on_every_node() {
    use crate::node::objects::vault_key_tx::apply_chain_vault_key;
    use crate::vault_key_tx::{KeyApply, VaultKey, VaultKeyHeader};
    struct Who {
        pk: Vec<u8>,
        sk: Vec<u8>,
        vid: [u8; 32],
        locked: Vec<u8>,
    }
    let who = |tag: &[u8]| -> Who {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let mut locked = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        locked[..32].copy_from_slice(Hash32::hash(tag).as_bytes());
        Who { vid: crate::pqauth::pubkey_id(&pk), pk, sk, locked }
    };
    let (owner_ek, _dk) = crate::pqkem::keypair();
    let clue = crate::unbond_tx::unbond_clue_for_test(&crate::account_da::bucket_id(b"r4b-owner"), &owner_ek);
    let verifier = crate::pqauth::MlDsaVerifier;
    let carry = |a: &mut Node, b: &mut Node, ts: u64, tag: &[u8]| -> u64 {
        let blk = a.produce(ts, Hash32::hash(tag), Hash32::hash(b"r4b-mc")).expect("A produces");
        let _ = b.ingest_block(blk, ts + 400);
        a.fold_past_for_test(&mut [b], ts + 400, tag)
    };
    const W_OWN: u128 = 150_000;
    for held in [true, false] {
        let (v, w) = (who(if held { b"r4b-held-v" } else { b"r4b-free-v" }), who(if held { b"r4b-held-w" } else { b"r4b-free-w" }));
        let (mut a, mut b) = (dd_node(), dd_node());
        for n in [&mut a, &mut b] {
            let mut gp = n.params().clone();
            gp.governance_set_stake_lock_blocks(0);
            gp.merge_depth_cap = 4;
            gp.governance_set_unbonding_blocks(0);
            gp.governance_set_miner_quarter_keys(6);
            n.set_params(gp);
            n.admit_bond_unverified(v.vid, 50_000, v.locked.clone(), 0);
            n.admit_bond_unverified(w.vid, W_OWN, w.locked.clone(), 0);
            if held {
                // the vault's ledgers stand moved (the test seam the gate's own pin uses): coins may sit under its keys
                let paid = n.peg.stake_paid_commit();
                n.peg.set_custody_commits_for_test(lanes(&[0x6a7e, 1, 0, 0]), lanes(&[0x6a7e, 2, 0, 0]), paid);
            }
        }
        if held {
            let mut ids = vec![v.vid, w.vid];
            ids.sort_unstable();
            let msg = b.peg().vault_key_take_msg(0, &b.vault_btc_key(0), &ids, b"");
            let attestors = [&v, &w]
                .iter()
                .map(|s| crate::psm::MintAttestor { pubkey: s.pk.clone(), sig: crate::pqauth::ml_dsa_sign(&msg, &s.sk).expect("the key signs") })
                .collect();
            let key = VaultKey { attestors, header: VaultKeyHeader::Take { vault: 0, members: ids, xmr_address: Vec::new() } };
            for n in [&mut a, &mut b] {
                assert!(matches!(apply_chain_vault_key(n, &key.wire(), Some(1), &verifier), KeyApply::Taken), "V and W take the key of their set");
            }
        }
        // V unbonds, through A's block
        let (sig, nonce) = a.sign_unbond_for_test(&v.sk, &v.vid, &clue);
        assert_eq!(a.publish_unbond(&v.pk, &sig, &clue, nonce), AssetSpendOutcome::Published, "V's unbond is published");
        let ts = carry(&mut a, &mut b, 5_000, b"r4b-unbond");
        assert!(b.validators().bond_of(&v.vid) == 0 && b.unbonding_due(&v.vid).is_some(), "V's weight left and its collateral waits, on the peer");
        let mut ts = a.fold_past_unbond_window_for_test(&mut [&mut b], ts, b"r4b-window");
        assert_eq!(b.unbonding_due(&v.vid).is_some(), held, "PRECONDITION: past its window, V is still held exactly when an alive key names it (held = {held})");
        // the bonders earn (a quarter of a 4,000 fee), and the chain folds on until the quarter closes
        for n in [&mut a, &mut b] {
            assert!(n.peg.credit_fee_pools_capped(4_000, 0, u64::MAX));
        }
        let y0 = b.peg().bond_yield_index();
        let before = |n: &Node| (n.own_yield_due(&w.vid, y0), n.own_yield_due(&v.vid, y0));
        let due0 = before(&b);
        assert_eq!(before(&a), due0, "PRECONDITION: both nodes hold the same accruals before the close");
        let mut tip_before = a.selected_tip().expect("A's tip");
        let mut steps = 0;
        while b.peg().bond_yield_index() == y0 {
            tip_before = a.selected_tip().expect("A's tip");
            ts = carry(&mut a, &mut b, ts + 1_000, b"r4b-quarter");
            steps += 1;
            assert!(steps <= 16, "PRECONDITION: a six-key quarter closes within sixteen blocks");
        }
        let y1 = b.peg().bond_yield_index();
        let quarter = crate::peg::bond_yield_between(W_OWN, y0, y1);
        assert!(quarter > 0 && a.peg().bond_yield_index() == y1, "PRECONDITION: the quarter closed with yield for W's weight, at one index on both nodes");
        let after = |n: &Node| (n.own_yield_due(&w.vid, y1), n.own_yield_due(&v.vid, y1));
        for (name, n) in [("A", &a), ("B", &b)] {
            let (w_due, v_due) = after(n);
            if held {
                assert_eq!(w_due, due0.0, "⛔ {name}: the member of a vault that holds a leaver past its window kept the quarter's yield");
                assert_eq!(v_due, due0.1 + quarter, "⛔ {name}: the held leaver was not credited exactly the member's own-weight yield of the quarter");
            } else {
                assert_eq!(w_due, due0.0 + quarter, "CALIBRATION, {name}: with no leaver held the member earns its quarter");
                assert_eq!(v_due, due0.1, "CALIBRATION, {name}: a leaver nobody holds is credited nothing");
            }
            assert_eq!(w_due + v_due, due0.0 + due0.1 + quarter, "⛔ {name}: the entitlements at the close are not what the index's rise gave W's weight");
        }
        eprintln!(
            "[vault-hostage] held={held}: the quarter closed after {steps} block(s); W's own-weight yield of it is {quarter}; W is due {} and V {} on the peer",
            after(&b).0,
            after(&b).1
        );
        if held {
            // REWIND: the closing step taken back restores both accruals and the index; folded again, A holds what B holds
            a.rewind_fold_to_common(tip_before);
            assert_eq!(a.peg().bond_yield_index(), y0, "the rewound close reopens the quarter");
            assert_eq!(before(&a), due0, "⛔ a rewound close left the diversion applied");
            assert_eq!(a.validators().own_yield_at(&w.vid, y1), due0.0 + quarter, "⛔ the rewound member no longer earns the quarter it had not yet forgone");
            let _ = a.fold_canonical_records();
            assert_eq!((a.peg().bond_yield_index(), after(&a)), (y1, after(&b)), "⛔ the close folded again gave A other accruals than the peer holds");
        }
        let _ = ts;
    }
}

/// ⛔⛔ SAFE AT SCALE, stage three (spec §3g.1; `Class::VaultRebalance`) — PART OF A VAULT'S LEDGER IS CARVED OUT,
/// HANDED OVER AND TAKEN BY ANOTHER VAULT ON EVERY NODE, AND EVERY FORGERY IS REFUSED. Twenty-five custodians are two
/// vaults (16 + 9); vault 1 takes a deposit (3,000 reserve, 2,000 minted) and an eighth of its Bitcoin bridge ledger (the
/// part the rule owes, 375 and 250) moves to vault 0. Nodes: A (a custodian of vault 1, the giver), B (signs as more of vault 1), W (a custodian of vault 0, the
/// receiver) and C (no seat: it takes everything from blocks).
///   • THE CARVE, proven from A's own opening, two thirds of vault 1. On the PEER C first: FORGE (five of nine; vault
///     0's members signing vault 1's carve), STRIP (a sum proof removed: no object; the minted proof replaced by the
///     reserve's) — each refused, C's ledgers unmoved. Then it rides A's block: C holds the giver on its pair after and
///     the part in the giver's slot; A's opening follows it (found from its own opening, never on the object's word).
///   • THE HAND-OVER (`opening_share`, kind PART): W asks for the slot's part; a node with no seat and a custodian of
///     the receiving vault answer nothing; A answers; W keeps it. A LYING GIVER's envelope (well-formed, sealed to W's
///     real key, holding an opening that is not the slot's part) is refused and nothing is kept.
///   • THE TAKE, proven from W's own opening and the part it was handed, two thirds of vault 0 under its bound after.
///     On C first: FORGE (ten of sixteen; vault 1's members taking for vault 0), SUBSTITUTE (the bound dropped while
///     only vault 0 signs), a take of a slot nobody carved — each refused. Then it rides W's block: C holds both
///     vaults on the stated pairs and no slot; every node holds the same; A and W open their new pairs; the giver's
///     kept part and the receiver's handed part are gone. REPLAY of either step on C: refused, nothing moved.
/// TWO-PARTY-REVIEWED: each object reaches C only in a block; every pair, slot and refusal is asserted on C.
#[test]
fn safe_at_scale_part_of_a_vaults_ledger_moves_to_another_vault_on_both_nodes_and_every_forgery_is_refused() {
    use crate::node::objects::vault_rebalance_tx::apply_chain_vault_rebalance;
    use crate::node::opening_share::{OpeningShare, KIND_PART};
    use crate::peg::PegLedger;
    use crate::psm::BondQuorum;
    use crate::vault_rebalance_tx::{RebalanceApply, VaultRebalance, VaultRebalanceHeader as H};
    let (mut a, mut b, mut w, mut c) = (testnet_node(), testnet_node(), testnet_node(), testnet_node());
    let seats = seat_all(&mut [&mut a, &mut b, &mut w, &mut c], 25);
    let vaults = c.custody_vaults();
    assert_eq!(vaults.iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 9]);
    let of = |v: usize| -> Vec<&Seat> { seats.iter().filter(|s| vaults[v].contains(&s.id)).collect() };
    let (v0, v1) = (of(0), of(1));
    a.set_custodian_identity(v1[0].id, v1[0].dk.clone());
    w.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    let verifier = crate::pqauth::MlDsaVerifier;
    let (btc, xmr) = (crate::peg::NATIVE_PEG_ASSET_ID, crate::peg::XMR_PEG_ASSET_ID);
    let _dep = vault_deposit(&mut a, &mut b, &mut [&mut w, &mut c], &v1, 1, 3_000, 2_000, 1_000, 1);
    let held = |n: &Node| (pair(n, 0, btc), pair(n, 0, xmr), pair(n, 1, btc), pair(n, 1, xmr), n.peg().vault_part(1).cloned());
    let before = held(&c);
    let commits = |o: crate::peg::LedgerOpening| PegLedger::commits_of_opening(o.0, o.1, o.2, o.3);
    let refused = |c: &mut Node, r: &VaultRebalance| apply_chain_vault_rebalance(c, &r.wire(), Some(1), &verifier);
    let ride_block = |by: &mut Node, others: &mut [&mut Node], r: &VaultRebalance, ts: u64, tag: &[u8]| {
        let bits = by.mempool().required_stamp_bits();
        assert!(by.ingest_tx(r.as_pq_tx(bits)).is_ok(), "the step is pooled");
        let blk = by.produce(ts, Hash32::hash(tag), Hash32::hash(b"vault-mc")).expect("the step rides a block");
        for n in others.iter_mut() {
            n.ingest_block(blk.clone(), ts + 400);
        }
        let _ = by.fold_past_blocks_for_test(others, ts, 50, tag);
    };

    // ── THE CARVE: half of vault 1's Bitcoin bridge ledger for vault 0, proven from A's own opening ──
    let from_open = a.fresh_bridge_openings().expect("A opens its vault's ledgers after the deposit");
    assert_eq!((from_open[0].0, from_open[0].2), (3_000, 2_000), "PRECONDITION: vault 1's Bitcoin ledger holds the deposit");
    let (leg, part, from_after) = c.peg().prove_vault_carve_leg(1, btc, from_open[0], (375, 250)).expect("the carve proves against the peer's own pair");
    let legs = vec![leg];
    let posts = PegLedger::rebalance_posts(&legs);
    assert_eq!(a.peg().vault_carve_msg(1, 0, &posts), c.peg().vault_carve_msg(1, 0, &posts), "every node derives the same carve from its own chain's pairs");
    let carve_msg = c.peg().vault_carve_msg(1, 0, &posts);
    let carve = VaultRebalance { header: H::Carve { from: 1, into: 0 }, legs, ride: Vec::new(), sigs: sign(&v1[..6], &carve_msg) };
    let forged = VaultRebalance { sigs: sign(&v1[..5], &carve_msg), ..carve.clone() };
    assert!(matches!(refused(&mut c, &forged), RebalanceApply::Refused(crate::peg::PegOutcome::InsufficientThreshold)), "⛔ FORGE: five of nine carved part of their vault's ledger on the peer");
    let by_other = VaultRebalance { sigs: sign(&v0[..11], &carve_msg), ..carve.clone() };
    assert!(matches!(refused(&mut c, &by_other), RebalanceApply::Refused(crate::peg::PegOutcome::InsufficientThreshold)), "⛔ FORGE: another vault's members carved part of this vault's ledger");
    let mut stripped = carve.clone();
    stripped.legs[0].minted_sum.clear();
    assert!(matches!(refused(&mut c, &stripped), RebalanceApply::NotRebalance), "⛔ STRIP: a carve with a sum proof removed was read as an object");
    let mut hollow = carve.clone();
    hollow.legs[0].minted_sum = hollow.legs[0].reserve_sum.clone();
    assert!(matches!(refused(&mut c, &hollow), RebalanceApply::Refused(crate::peg::PegOutcome::BadRequest)), "⛔ STRIP: the minted sum's proof replaced by the reserve's was taken");
    assert_eq!(held(&c), before, "⛔ a refused carve changed the peer's ledgers");
    ride_block(&mut a, &mut [&mut b, &mut w, &mut c], &carve, 60_000, b"vault-carve");
    let slot = c.peg().vault_part(1).cloned().expect("⛔ the PEER holds no part in the giver's slot");
    assert_eq!((slot.into, slot.legs.len(), slot.legs[0].part, slot.legs[0].from_post), (0, 1, commits(part), commits(from_after)), "the slot names the receiver and the part");
    assert_eq!((pair(&c, 1, btc), pair(&c, 0, btc)), (commits(from_after), before.0), "⛔ the peer moved a ledger the carve does not move");
    assert_eq!(held(&c), held(&a), "every node holds the same pairs and slot");
    assert_eq!(held(&c), held(&w));
    let a_after = a.fresh_bridge_openings().expect("⛔ the giving custodian does not open the pair it now stands behind");
    assert_eq!((a_after[0].0, a_after[0].2), (2_625, 1_750), "seven eighths stay with the giver");
    assert!(a.rebalance_held_opening(Node::REBALANCE_PART, btc, slot.legs[0].part).is_some(), "the giving custodian keeps the part it carved");

    // ── THE HAND-OVER: W asks for the part, A gives it, W keeps it ──
    let asks: Vec<OpeningShare> = w.opening_share_asks().into_iter().filter(|s| matches!(s, OpeningShare::Ask { kind, .. } if *kind == KIND_PART)).collect();
    assert_eq!(asks.len(), 1, "⛔ the receiving custodian does not ask for the part at rest for its vault");
    assert!(c.opening_share_answer(&asks[0]).is_none(), "⛔ a node with no seat answered for the part");
    let give = a.opening_share_answer(&asks[0]).expect("a custodian of the giving vault answers");
    // a LYING GIVER: its own envelope, sealed to W's real key, holding an opening that is not the slot's part
    if let OpeningShare::Give { kind, key, words, to, .. } = &give {
        let body = postcard::to_stdvec(&(from_after, from_after)).expect("encodes");
        let sealed = crate::node::opening_share::seal_for_test(&v0[0].ek, &body).expect("seals");
        let lie = OpeningShare::Give { kind: *kind, key: *key, words: *words, to: *to, sealed };
        assert!(!w.opening_share_take(&lie), "⛔ LYING GIVER: an opening that is not the slot's part was kept");
    }
    assert!(w.rebalance_held_opening(Node::REBALANCE_IN, btc, slot.legs[0].part).is_none(), "⛔ a refused give left something kept");
    assert!(w.opening_share_take(&give), "the receiving custodian keeps the part");
    let handed = w.rebalance_held_opening(Node::REBALANCE_IN, btc, slot.legs[0].part).expect("the part opens the slot's commitments");
    assert_eq!((handed.0, handed.2), (375, 250), "the part as carved");
    assert!(w.opening_share_asks().iter().all(|s| !matches!(s, OpeningShare::Ask { kind, .. } if *kind == KIND_PART)), "a custodian that holds the part asks no more");

    // ── THE TAKE: vault 0 adds the part, from W's own opening and the part it was handed ──
    let into_open = w.fresh_bridge_openings().expect("W opens its vault's ledgers");
    let (tleg, into_after) = c.peg().prove_vault_part_added_leg(1, 0, btc, into_open[0], handed).expect("the take proves against the peer's own pair and slot");
    let (_, forfeit0) = c.validators().vault(0).expect("vault 0 exists");
    let ride = c.peg().prove_vault_ride(0, forfeit0, &[into_after, into_open[1]]).expect("after the take vault 0 stands inside its authority").encode();
    let tlegs = vec![tleg];
    let take_msg = c.peg().vault_take_msg(1, &PegLedger::rebalance_posts(&tlegs));
    assert_eq!(take_msg, w.peg().vault_take_msg(1, &PegLedger::rebalance_posts(&tlegs)), "every node derives the same take from its own chain's slot and pairs");
    let take = VaultRebalance { header: H::Take { from: 1 }, legs: tlegs, ride, sigs: sign(&v0[..11], &take_msg) };
    let mid = held(&c);
    let forged = VaultRebalance { sigs: sign(&v0[..10], &take_msg), ..take.clone() };
    assert!(matches!(refused(&mut c, &forged), RebalanceApply::Refused(crate::peg::PegOutcome::InsufficientThreshold)), "⛔ FORGE: ten of sixteen took the part on the peer");
    let by_giver = VaultRebalance { sigs: sign(&v1[..8], &take_msg), ..take.clone() };
    assert!(matches!(refused(&mut c, &by_giver), RebalanceApply::Refused(crate::peg::PegOutcome::InsufficientThreshold)), "⛔ FORGE: the giving vault's members took the part on the receiver's behalf");
    let no_bound = VaultRebalance { ride: Vec::new(), ..take.clone() };
    assert!(matches!(refused(&mut c, &no_bound), RebalanceApply::Refused(crate::peg::PegOutcome::InsufficientThreshold)), "⛔ SUBSTITUTE: the receiver's quorum took a part with its bound proof dropped");
    let nobody = VaultRebalance { header: H::Take { from: 0 }, ..take.clone() };
    assert!(matches!(refused(&mut c, &nobody), RebalanceApply::Refused(crate::peg::PegOutcome::Replay)), "⛔ a take of a slot nobody carved was taken");
    assert_eq!(held(&c), mid, "⛔ a refused take changed the peer's ledgers");
    ride_block(&mut w, &mut [&mut a, &mut b, &mut c], &take, 70_000, b"vault-take");
    assert_eq!((pair(&c, 1, btc), pair(&c, 0, btc)), (commits(from_after), take.legs[0].post), "⛔ the PEER does not hold both vaults on the stated pairs");
    assert!(c.peg().vault_part(1).is_none(), "⛔ the slot outlived its take on the peer");
    assert_eq!((pair(&c, 0, xmr), pair(&c, 1, xmr)), (before.1, before.3), "⛔ the move touched a ledger it does not name on the peer");
    assert_eq!(held(&c), held(&a), "every node holds the same pairs");
    assert_eq!(held(&c), held(&w));
    let (a_now, w_now) = (a.fresh_bridge_openings().expect("the giver still opens its pair"), w.fresh_bridge_openings().expect("⛔ the receiving custodian does not open the pair it now stands behind"));
    assert_eq!((a_now[0].0, a_now[0].2, w_now[0].0, w_now[0].2), (2_625, 1_750, 375, 250), "seven eighths stay with the giver, an eighth stands with the receiver: nothing created, nothing lost");
    assert!(a.rebalance_held_opening(Node::REBALANCE_PART, btc, slot.legs[0].part).is_none() && w.rebalance_held_opening(Node::REBALANCE_IN, btc, slot.legs[0].part).is_none(), "⛔ a closed slot's part is still kept");
    // REPLAY of either step on the peer
    let after = held(&c);
    assert!(matches!(refused(&mut c, &take), RebalanceApply::Refused(_)), "⛔ REPLAY: the settled take was taken again on the peer");
    assert!(matches!(refused(&mut c, &carve), RebalanceApply::Refused(_)), "⛔ REPLAY: the settled carve was carved again on the peer");
    assert_eq!(held(&c), after);
}

/// ⛔⛔ SAFE AT SCALE, stage three (spec §3g.1) — THE REBALANCE LANE ITSELF: a vault past its bound carves the part its own
/// custodians' openings owe, for the vault the chain's rule names; the receiver consents once it holds the part and has room;
/// it takes once its own sources show the coins — every statement each custodian's own derivation, every step framed by a
/// custodian holding two thirds of its vault, every one applied from a block. Twenty-five custodians are two vaults (16 + 9);
/// vault 1 takes a deposit (3,000 reserve, 2,000 minted); then SAT's price falls so vault 1's bonds repay 1,800 while vault 0's
/// repay more. Nodes: A (vault 1), B (more of vault 1), W (vault 0), C (no seat).
///   • THE CARVE: A's chain names vault 0 as the receiver and an eighth of both words (375, 250) — the smallest listed part
///     that brings 2,000 inside 1,800. Six of nine sign the carve their own openings derive; A frames it; C holds the slot.
///     REFUSED in the lane: a signature of vault 0's members over vault 1's carve is not counted; a LYING carve (a quarter
///     instead of the eighth) signed by all nine is never framed — the framer frames only the statement its own openings
///     derive. NEVER signed: a carve by a vault inside its bound (CALIBRATION before the price fell).
///   • THE CONSENT: before its vault holds a key W consents to nothing; with vault 0's key recorded and the part handed over,
///     eleven of sixteen consent and A reads that key as the one to send to. Before the hand-over: no consent (no part held).
///   • THE TAKE: with no coins seen, W signs no take; with its sources showing them, eleven sign; W frames it under vault 0's
///     bound; C holds both vaults on the pairs after, no slot, and the two ledgers add to the deposit.
///   • THE CANCEL RULE: inside the rotation day A signs no cancel, moved or not.
/// TWO-PARTY-REVIEWED: every step reaches C only in a block; every pair and slot is asserted on C.
#[test]
fn safe_at_scale_a_vault_past_its_bound_carves_its_owed_part_and_the_receiver_takes_it_once_its_own_sources_show_the_coins() {
    use crate::node::opening_share::{OpeningShare, KIND_PART};
    use crate::psm::BondQuorum;
    use crate::vault_key_tx::{VaultKey, VaultKeyHeader};
    use crate::vault_rebalance_tx::{RebalanceStatement, VaultRebalanceHeader as H, VaultRebalanceSig};
    let (mut a, mut b, mut w, mut c) = (testnet_node(), testnet_node(), testnet_node(), testnet_node());
    let seats = seat_all(&mut [&mut a, &mut b, &mut w, &mut c], 25);
    let vaults = c.custody_vaults();
    assert_eq!(vaults.iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 9]);
    let of = |v: usize| -> Vec<&Seat> { seats.iter().filter(|s| vaults[v].contains(&s.id)).collect() };
    let (v0, v1) = (of(0), of(1));
    a.set_custodian_identity(v1[0].id, v1[0].dk.clone());
    w.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    let verifier = crate::pqauth::MlDsaVerifier;
    let btc = crate::peg::NATIVE_PEG_ASSET_ID;
    let _dep = vault_deposit(&mut a, &mut b, &mut [&mut w, &mut c], &v1, 1, 3_000, 2_000, 1_000, 1);
    assert!(a.rebalance_carve_due().is_none(), "CALIBRATION: a vault inside its bound owes no part");
    let none = |_: u32, _: u32| false;
    let not_moved = |_: u32| false;
    assert!(a.own_rebalance_sigs(&v1[0].pk, &v1[0].sk, &none, &not_moved).is_empty(), "CALIBRATION: a vault inside its bound signs nothing");
    // SAT falls: vault 1's bonds now repay 1,800 USDm atomic (the price that does it read from its own authority)
    let (_, forfeit1) = c.validators().vault(1).expect("vault 1");
    let (_, forfeit0) = c.validators().vault(0).expect("vault 0");
    let at_two = c.peg().vault_authority_usdm(forfeit1).expect("SAT is priced");
    let price = 2 * crate::liquidation::PRICE_SCALE * 1_800 / at_two;
    for n in [&mut a, &mut b, &mut w, &mut c] {
        n.peg.set_price_mark_for_test(crate::peg::SAT_PRICE_ASSET_ID, price, 2);
    }
    let auth1 = c.peg().vault_authority_usdm(forfeit1).expect("priced");
    let auth0 = c.peg().vault_authority_usdm(forfeit0).expect("priced");
    assert!(auth1 < 2_000 && auth1 >= 1_750 && auth0 >= 2_000, "PRECONDITION: vault 1 past its bound, by less than an eighth; vault 0 with room ({auth1}, {auth0})");
    let sign_as = |n: &mut Node, s: &Seat| -> Vec<VaultRebalanceSig> {
        n.set_custodian_identity(s.id, s.dk.clone());
        n.own_rebalance_sigs(&s.pk, &s.sk, &none, &not_moved)
    };
    let ride_block = |by: &mut Node, others: &mut [&mut Node], r: &crate::vault_rebalance_tx::VaultRebalance, ts: u64, tag: &[u8]| {
        let bits = by.mempool().required_stamp_bits();
        assert!(by.ingest_tx(r.as_pq_tx(bits)).is_ok(), "the step is pooled");
        let blk = by.produce(ts, Hash32::hash(tag), Hash32::hash(b"vault-mc")).expect("the step rides a block");
        for n in others.iter_mut() {
            n.ingest_block(blk.clone(), ts + 400);
        }
        let _ = by.fold_past_blocks_for_test(others, ts, 50, tag);
    };
    let frame = |n: &mut Node| -> crate::vault_rebalance_tx::VaultRebalance {
        let (sigs, inputs) = n.rebalance_ready_to_frame(&crate::pqauth::MlDsaVerifier).expect("two thirds of the vault stand behind the step");
        let mut r = inputs.prove().expect("the step proves from this custodian's openings");
        r.sigs = sigs;
        assert!(matches!(n.rebalance_door_takes(&r), crate::peg::PegOutcome::ConfidentialPublished), "⛔ the framer's own door would refuse the step it framed: {:?}", n.rebalance_door_takes(&r));
        r
    };

    // ── THE CARVE ──
    let (from, into, legs) = a.rebalance_carve_due().expect("⛔ a vault past its bound owes no part on its own custodian's chain");
    assert_eq!((from, into), (1, 0), "the chain's rule names the other vault");
    assert_eq!(legs.iter().map(|(k, _, p)| (*k, *p)).collect::<Vec<_>>(), vec![(btc, (375, 250))], "an eighth of both words of the moved ledger, the smallest listed part that brings 2,000 inside {auth1}");
    let mine = a.own_rebalance_sigs(&v1[0].pk, &v1[0].sk, &none, &not_moved);
    assert!(mine.iter().any(|s| matches!(s.stmt, RebalanceStatement::Carve { from: 1, into: 0, .. })), "the custodian signs the carve its own openings derive");
    for s in &mine {
        assert!(a.rebalance_sig_ingest(&VaultRebalanceSig::decode(&s.wire()).expect("one encoding"), &verifier), "A keeps its own carve signature");
    }
    // a LYING carve — a quarter, not the eighth — signed by all nine: the lane keeps it, and never frames it
    let honest_posts = match &mine.iter().find(|s| matches!(s.stmt, RebalanceStatement::Carve { .. })).expect("a carve").stmt {
        RebalanceStatement::Carve { posts, .. } => posts.clone(),
        _ => unreachable!(),
    };
    let quarter = a.fresh_bridge_openings().map(|o| crate::peg::PegLedger::giver_opening_after_rebalance(o[0], (750, 500))).flatten().expect("a quarter derives");
    let commits = |o: crate::peg::LedgerOpening| crate::peg::PegLedger::commits_of_opening(o.0, o.1, o.2, o.3);
    let lie_posts = vec![(btc, Some(commits(quarter.0)), commits(quarter.1))];
    assert_ne!(lie_posts, honest_posts, "CALIBRATION: the lie is another statement");
    let lie_msg = a.peg().vault_carve_msg(1, 0, &lie_posts);
    for s in &v1 {
        let lie = VaultRebalanceSig { stmt: RebalanceStatement::Carve { from: 1, into: 0, posts: lie_posts.clone() }, pubkey: s.pk.clone(), sig: crate::pqauth::ml_dsa_sign(&lie_msg, &s.sk).expect("signs") };
        let _ = a.rebalance_sig_ingest(&lie, &verifier);
    }
    // a stranger's signature over the honest carve: a member of vault 0 is not counted
    let stranger = VaultRebalanceSig { stmt: RebalanceStatement::Carve { from: 1, into: 0, posts: honest_posts.clone() }, pubkey: v0[3].pk.clone(), sig: crate::pqauth::ml_dsa_sign(&a.peg().vault_carve_msg(1, 0, &honest_posts), &v0[3].sk).expect("signs") };
    assert!(!a.rebalance_sig_ingest(&stranger, &verifier), "⛔ a member of another vault was counted on this vault's carve");
    assert!(a.rebalance_ready_to_frame(&verifier).is_none(), "⛔ a lie nine signed was framed, or one honest signature was enough");
    // A signs again what its own openings derive (its lane does every tick): a signer's newer statement replaces its older
    for s in a.own_rebalance_sigs(&v1[0].pk, &v1[0].sk, &none, &not_moved) {
        let _ = a.rebalance_sig_ingest(&s, &verifier);
    }
    for s in &v1[1..6] {
        for x in sign_as(&mut b, s) {
            let _ = a.rebalance_sig_ingest(&x, &verifier);
        }
    }
    let carve = frame(&mut a);
    assert_eq!(carve.header, H::Carve { from: 1, into: 0 }, "⛔ the framed step is not the carve the custodians derived");
    assert_eq!(carve.legs.iter().map(|l| (l.asset, l.part, l.post)).collect::<Vec<_>>(), vec![(btc, honest_posts[0].1, honest_posts[0].2)], "⛔ LYING STATEMENT: the framed carve is not the one the framer's own openings derive");
    ride_block(&mut a, &mut [&mut b, &mut w, &mut c], &carve, 60_000, b"lane-carve");
    let slot = c.peg().vault_part(1).cloned().expect("⛔ the PEER holds no part in the giver's slot");
    assert_eq!(slot.into, 0, "the slot names the receiver");
    assert!(a.rebalance_carve_due().is_none(), "a vault with a part at rest owes no second one");

    // ── THE CONSENT ──
    let consents = |n: &mut Node, who: &[&Seat]| -> Vec<VaultRebalanceSig> {
        who.iter().flat_map(|s| sign_as(n, s)).filter(|x| matches!(x.stmt, RebalanceStatement::Consent { .. })).collect()
    };
    assert!(consents(&mut w, &v0[..1]).is_empty(), "⛔ a custodian consented to a part it does not hold, for a vault with no key");
    // vault 0 records a key (a take signed by eleven of its sixteen), on every node at one blue score
    let mut ids: Vec<[u8; 32]> = v0.iter().map(|s| s.id).collect();
    ids.sort_unstable();
    let key_msg = c.peg().vault_key_take_msg(0, &c.vault_btc_key(0), &ids, b"");
    let key = VaultKey { attestors: sign(&v0[..11], &key_msg), header: VaultKeyHeader::Take { vault: 0, members: ids, xmr_address: Vec::new() } };
    for n in [&mut a, &mut b, &mut w, &mut c] {
        assert!(matches!(n.apply_vault_key(&key, 61, &verifier), crate::peg::PegOutcome::ConfidentialMinted), "every node records vault 0's key");
    }
    w.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    assert!(consents(&mut w, &v0[..1]).is_empty(), "⛔ a custodian consented before it held the part");
    w.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    let ask = w.opening_share_asks().into_iter().find(|s| matches!(s, OpeningShare::Ask { kind, .. } if *kind == KIND_PART)).expect("the receiver asks for the part");
    a.set_custodian_identity(v1[0].id, v1[0].dk.clone());
    let give = a.opening_share_answer(&ask).expect("the giver answers");
    assert!(w.opening_share_take(&give), "the receiver keeps the part");
    let given = consents(&mut w, &v0[..11]);
    assert_eq!(given.len(), 11, "eleven of vault 0's custodians, each holding the part and room for it, consent");
    for s in &given {
        let x = VaultRebalanceSig::decode(&s.wire()).expect("one encoding");
        let _ = w.rebalance_sig_ingest(&x, &verifier);
        assert!(a.rebalance_sig_ingest(&x, &verifier), "the giver keeps the receiver's consent");
    }
    assert_eq!(a.rebalance_send_key(1).map(|k| k.since_tick), Some(61), "⛔ the giver does not read the receiver's consented current key as where the coins go");

    // ── THE TAKE ──
    w.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    assert!(w.own_rebalance_sigs(&v0[0].pk, &v0[0].sk, &none, &not_moved).iter().all(|x| !matches!(x.stmt, RebalanceStatement::Take { .. })), "⛔ a custodian signed the take before its own sources showed the coins");
    let seen = |_: u32, _: u32| true;
    for s in &v0[..11] {
        w.set_custodian_identity(s.id, s.dk.clone());
        for x in w.own_rebalance_sigs(&s.pk, &s.sk, &seen, &not_moved).into_iter().filter(|x| matches!(x.stmt, RebalanceStatement::Take { .. })) {
            assert!(w.rebalance_sig_ingest(&x, &verifier), "the receiver keeps its members' takes");
        }
    }
    w.set_custodian_identity(v0[0].id, v0[0].dk.clone());
    let take = frame(&mut w);
    assert_eq!(take.header, H::Take { from: 1 }, "the framed step is the take");
    assert!(!take.ride.is_empty(), "the take rides vault 0's own bound proof");
    ride_block(&mut w, &mut [&mut a, &mut b, &mut c], &take, 70_000, b"lane-take");
    assert!(c.peg().vault_part(1).is_none(), "⛔ the slot outlived its take on the peer");
    let (a_now, w_now) = (a.fresh_bridge_openings().expect("the giver opens its pair"), w.fresh_bridge_openings().expect("the receiver opens its pair"));
    assert_eq!((a_now[0].0 + w_now[0].0, a_now[0].2 + w_now[0].2), (3_000, 2_000), "⛔ the two ledgers no longer add to the deposit");
    assert_eq!((w_now[0].0, w_now[0].2), (375, 250), "the part stands with the receiver");

    // ── THE CANCEL RULE (inside the rotation day) ──
    a.set_custodian_identity(v1[0].id, v1[0].dk.clone());
    let moved = |_: u32| true;
    assert!(a.own_rebalance_sigs(&v1[0].pk, &v1[0].sk, &none, &moved).iter().chain(a.own_rebalance_sigs(&v1[0].pk, &v1[0].sk, &none, &not_moved).iter()).all(|x| !matches!(x.stmt, RebalanceStatement::Cancel { .. })), "⛔ a cancel was signed with no part at rest or inside the day");
}
