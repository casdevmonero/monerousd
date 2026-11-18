// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `asset_tx::tests` — the tests of `asset_tx` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `asset_tx` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`asset_tx::tests::…`), and `use super::*` reaches `asset_tx`'s items through the node's re-export.

// the imports of `asset_tx` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use serde::Deserialize;
#[allow(unused_imports)]
use serde::Serialize;

use super::{AssetCreateTx, AssetKind, AssetMintTx};

/// ⭐⭐⭐ THE SMART-CONTRACT LAYER IS CONSENSUS STATE: TWO NODES REACH THE SAME REGISTRY ROOT.
///
/// ⛔ IT WAS NOT. The registry lived in the web server's memory (`sovereign.rs`:
/// `Arc<Mutex<DsolRegistry>>`), so a creation registered in one process and nowhere else and two nodes
/// held two registries — this file's own header records it as *"the project's root error a third and
/// fourth time: a local computation returned as if it were a state change."* A token that exists on
/// one node and not another is not an asset, and anything denominated in it is unsafe to hold.
///
/// The registry now lives on the NODE and the graft-side door writes it, so this asserts the only
/// thing that makes an asset real: a SECOND node, which never saw the creation until the bytes
/// arrived, ends at the same root as the first.
#[test]
fn two_nodes_applying_the_same_creation_reach_the_same_registry_root() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    assert_eq!(
        a.token_registry_root(),
        b.token_registry_root(),
        "PRECONDITION: two fresh nodes agree on an empty registry"
    );
    let empty = a.token_registry_root();

    // §BR-14: the creation pays — its fee note is funded and folded on both nodes first.
    let mut c = a_token();
    crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut c, 1, 5_000);
    let blob = c.wire();
    let ra = crate::node::objects::asset_tx::apply_chain_asset_object(&mut a, &blob);
    let rb = crate::node::objects::asset_tx::apply_chain_asset_object(&mut b, &blob);
    assert!(
        matches!(ra, super::AssetApply::Created(_)),
        "the creation applies on the first node: {ra:?}"
    );
    assert!(
        matches!(rb, super::AssetApply::Created(_)),
        "and on the second, which never saw it before: {rb:?}"
    );
    assert_ne!(a.token_registry_root(), empty, "the registry root MOVED");
    assert_eq!(
        a.token_registry_root(),
        b.token_registry_root(),
        "⛔ AND BOTH NODES END AT THE SAME ROOT. If they do not, the token exists on one node and \
         not the other, which is the two-registries class this replaced."
    );

    let (count, peaks) = a.dsol_registry_size();
    assert_eq!(count, 1, "one asset registered");
    assert!(
        peaks <= crate::dsol::MMR_MAX_PEAKS,
        "the registry is an append-only mountain range: {peaks} peak(s), never a map of descriptors"
    );
}

/// A mint of `c`'s whole NFT, signed by the creator's key `sk`, stating `logo` and filing under `collection`. The
/// note is a shape only (this builds the object the mint door AUTHORISES; the carrier is the credit gate's, pinned
/// elsewhere).
fn nft_mint_for_test(c: &AssetCreateTx, pk: &[u8], sk: &[u8], logo: [u8; 32], collection: &str) -> super::AssetMintTx {
    let cm = crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&[0x126, 1, 2, 3]));
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..32].copy_from_slice(&cm);
    let owner_clue = vec![0x5cu8; crate::peg_in_tx::OWNER_CLUE_MAX];
    let msg = super::asset_mint_msg(&c.asset_id, 1, &cm, &crate::oli::owner_clue_digest(&owner_clue), collection);
    super::AssetMintTx {
        asset_id: c.asset_id,
        kind: c.kind,
        amount: 1,
        note,
        mint_carrier: vec![1],
        owner_clue,
        creator_pubkey: pk.to_vec(),
        creator_sig: crate::pqauth::ml_dsa_sign(&msg, sk).expect("sign"),
        symbol: c.symbol.clone(),
        asset_name: c.name.clone(),
        registry_path: Vec::new(),
        registry_dirs: Vec::new(),
        logo,
        collection: collection.to_string(),
    }
}

/// An NFT creation by the key `creator`, binding `art`'s digest and carrying the bytes when `carry` is set.
fn pictured_nft(creator: [u8; 32], art: &[u8], carry: bool) -> AssetCreateTx {
    let mut c = AssetCreateTx {
        kind: AssetKind::Nft,
        symbol: "APE1".into(),
        name: "Ape One".into(),
        logo: *crate::hash::Hash32::hash(art).as_bytes(),
        bytecode: crate::dsol::compile(crate::dsol::DsolKind::Nft, "APE1", "Ape One").bytecode,
        creator,
        asset_id: [0u8; 32],
        fee: super::CreationFee::default(),
        art: if carry { art.to_vec() } else { Vec::new() },
        supply: None,
    };
    c.asset_id = c.derived_id();
    c
}

fn a_png(len: usize, tag: u8) -> Vec<u8> {
    let mut art = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    art.resize(len, tag);
    art
}

/// ⛔ FINDING A-F24 (2026-11-11) — AN ASSET CREATED WITH A PICTURE CAN BE MINTED BY ITS CREATOR.
///
/// WHAT WAS WRONG: a mint had no field for the picture digest its asset's identity binds, and rebuilt the identity
/// with a zero one. So for every asset created WITH a picture the rebuilt id was not the asset's id and every node
/// refused the mint, after the creation had burned its price: the creator paid and held nothing.
/// RED on the tree before `AssetMintTx::logo` (there the mint below cannot be built to verify at all: with a zero
/// logo, which is all a mint could state, `creator_authorised` is false, the first assertion's CALIBRATION twin).
/// THE ATTACK ROWS: a mint stating NO picture for a pictured asset, and one stating ANOTHER picture, are refused (the
/// digest is inside the id the signature covers), so the field cannot be used to mint into a different asset.
#[test]
fn af24_a_mint_of_an_asset_created_with_a_picture_is_its_creators() {
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let creator = crate::pqauth::pubkey_id(&pk);
    let art = a_png(2_000, 0x5a);
    let c = pictured_nft(creator, &art, true);
    assert_ne!(c.logo, [0u8; 32], "PRECONDITION: the asset's identity binds a picture");
    let v = crate::pqauth::MlDsaVerifier;
    let honest = nft_mint_for_test(&c, &pk, &sk, c.logo, "");
    assert!(
        honest.creator_authorised(&v),
        "⛔ A-F24: the creator's own mint of an asset created with a picture is refused: its creation price is burned and it can never have supply"
    );
    assert_eq!(honest.rebuilt_descriptor().id, crate::hash::Hash32(c.asset_id), "the mint rebuilds the id the creation registered");
    // what a mint could say before the field existed: no picture. That is another asset's id, and is refused
    assert!(!nft_mint_for_test(&c, &pk, &sk, [0u8; 32], "").creator_authorised(&v), "a mint stating no picture for a pictured asset verified");
    let other = *crate::hash::Hash32::hash(&a_png(2_000, 0x33)).as_bytes();
    assert!(!nft_mint_for_test(&c, &pk, &sk, other, "").creator_authorised(&v), "⛔ a mint stating another picture verified");
    // and another key cannot mint it, picture or not
    let (pk2, sk2) = crate::pqauth::ml_dsa_keypair();
    assert!(!nft_mint_for_test(&c, &pk2, &sk2, c.logo, "").creator_authorised(&v), "⛔ a key that did not create the asset minted it");
    // CALIBRATION: an asset with no picture mints as it always did
    let plain = pictured_nft(creator, &[], false);
    let mut plain = AssetCreateTx { logo: [0u8; 32], ..plain };
    plain.asset_id = plain.derived_id();
    assert!(nft_mint_for_test(&plain, &pk, &sk, [0u8; 32], "").creator_authorised(&v), "CALIBRATION: a mint of an asset with no picture verifies");
}

/// ⭐ SPEC §12.6 — AN ASSET'S NAME AND PICTURE ARE THE CHAIN'S, AND ITS COLLECTION IS ITS CREATOR'S TO SAY. Two nodes
/// that apply the same objects hold the same record, the same picture bytes and the same collection piece, with no
/// card handed to anyone. What nobody else can do:
///   * strip a pooled creation's picture (the burn's price counts the picture's kilobytes) or put another in its place (the picture
///     must hash to the digest the asset's identity binds): each is refused whole, writing nothing;
///   * keep the picture off the chain by creating the asset FIRST without it (a creation is not signed by the
///     creator it names): the creator's own creation then adds the true picture;
///   * choose the collection: it is said by the MINT, under the creator's signature, and a mint re-filed under
///     another of the creator's collections no longer verifies.
/// CALIBRATION: the untouched objects apply on both nodes, so each refusal was the tamper's.
/// TWO-PARTY-REVIEWED: the creator's node and a second node that sees only the objects' bytes.
#[test]
fn s126_a_creations_picture_and_its_mints_collection_reach_both_nodes_and_tampers_are_refused() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    // the creator's two collections, signed by the creator's key and applied on both nodes
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let creator = crate::pqauth::pubkey_id(&pk);
    let collection = |handle: &str| {
        let mut e = crate::directory::DirEntry {
            kind: crate::directory::KIND_COLLECTION,
            key: handle.into(),
            address: String::new(),
            name: handle.to_uppercase(),
            topic: String::new(),
            pubkey: pk.clone(),
            sig: Vec::new(),
            pic: None,
        };
        e.sig = crate::pqauth::ml_dsa_sign(&crate::directory::dir_entry_msg(&e), &sk).expect("sign");
        e
    };
    let set = crate::directory::encode_dir_set(&[collection("apes"), collection("bears")]);
    a.apply_dir_set(&set, 1);
    b.apply_dir_set(&set, 1);
    assert!(a.resolve_dir_collection("apes").is_some() && b.resolve_dir_collection("bears").is_some(), "PRECONDITION: both collections exist on both nodes");

    let art = a_png(3_000, 0x5a); // three started kilobytes
    let mut c = pictured_nft(creator, &art, true);
    assert_eq!(
        c.creation_price(),
        crate::params::NFT_CREATE_FEE_ATOMIC + 3 * crate::dir_entry_tx::DIR_KB_FEE_ATOMIC,
        "the price is the kind's plus one directory kilobyte price for each started kilobyte of picture"
    );
    // THE FRONT-RUN: someone else pays to create the same asset first, with no picture on the chain
    let mut first = pictured_nft(creator, &art, false);
    assert_eq!(first.asset_id, c.asset_id, "PRECONDITION: the same asset (the picture's bytes are not part of the id; its digest is)");
    let ts = crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut first, 125, 5_000);
    crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut c, 126, ts + 200);
    assert!(c.fee_carrier_verifies(), "CALIBRATION: the untouched creation's burn verifies");
    let id_hex: String = c.asset_id.iter().map(|x| format!("{x:02x}")).collect();
    for n in [&mut a, &mut b] {
        let r = crate::node::objects::asset_tx::apply_chain_asset_object(n, &first.wire());
        assert!(matches!(r, super::AssetApply::Created(_)), "the first creation applies: {r:?}");
        assert_eq!(n.resolve_dir_asset(&id_hex).map(|r| r.pic), Some(None), "CALIBRATION: the record exists and names no picture yet");
    }

    // ⛔ THE CREATION'S TWO TAMPERS, each refused on a node with nothing written
    let mut stripped = c.clone();
    stripped.art.clear();
    let mut swapped = c.clone();
    swapped.art[100] ^= 1;
    for (what, t) in [("with its picture stripped", &stripped), ("with its picture swapped", &swapped)] {
        let r = crate::node::objects::asset_tx::apply_chain_asset_object(&mut b, &t.wire());
        assert!(matches!(r, super::AssetApply::CreateRefused(_)), "⛔ a creation {what} applied: {r:?}");
        assert_eq!(b.resolve_dir_asset(&id_hex).map(|r| r.pic), Some(None), "⛔ a creation {what} changed the record");
    }

    // THE CREATOR'S OWN CREATION, on both nodes: the record gains the true picture despite the front-run
    let blob = c.wire();
    for (who, n) in [("the creator's node", &mut a), ("the second node", &mut b)] {
        let r = crate::node::objects::asset_tx::apply_chain_asset_object(n, &blob);
        assert!(matches!(r, super::AssetApply::Created(_)), "the creation applies on {who}: {r:?}");
        let rec = n.resolve_dir_asset(&id_hex).unwrap_or_else(|| panic!("{who} holds no record of the asset"));
        assert_eq!(
            (rec.nft, rec.symbol.as_str(), rec.name.as_str(), rec.creator, rec.logo, rec.pic, rec.collection.as_str()),
            (true, "APE1", "Ape One", creator, c.logo, Some(c.logo), ""),
            "{who} names the asset from the chain, with its picture, filed under nothing yet"
        );
        assert_eq!(n.dir_asset_art(&id_hex), art.as_slice(), "⛔ {who} does not hold the picture: creating the asset first kept it off the chain");
    }

    // THE MINT SAYS THE COLLECTION, under the creator's signature
    let v = crate::pqauth::MlDsaVerifier;
    let mint = nft_mint_for_test(&c, &pk, &sk, c.logo, "apes");
    assert!(mint.creator_authorised(&v), "CALIBRATION: the creator's mint, filing under apes, verifies");
    let mut refiled = mint.clone();
    refiled.collection = "bears".into();
    assert!(!refiled.creator_authorised(&v), "⛔ a mint re-filed under another collection still carries the creator's authority");
    for (who, n) in [("the creator's node", &mut a), ("the second node", &mut b)] {
        assert!(n.file_asset_at_fold(&mint), "{who} files the asset under the collection its mint names");
        assert!(!n.file_asset_at_fold(&mint), "an asset is filed once");
        assert_eq!(n.resolve_dir_asset(&id_hex).map(|r| r.collection.clone()), Some("apes".to_string()));
        assert_eq!(n.dir_collection_pieces_page("apes", 0, 8), (vec![c.asset_id], 1), "{who} lists it among the collection's pieces");
        assert_eq!(n.dir_collection_pieces_page("bears", 0, 8).1, 0, "the other collection gained nothing");
    }
    assert_eq!(a.dir_acc(), b.dir_acc(), "⛔ two nodes hold two directories for one chain");
}

/// ⭐⭐⭐ SUPPLY CANNOT EXIST FOR AN ASSET THIS CHAIN NEVER REGISTERED — refutation first.
///
/// The signature gate binds the minter to a descriptor. The credit gate binds the note to the claimed
/// amount. NEITHER asks whether the asset was ever created, so both pass for a descriptor whose
/// creation was never published — and the supply circulates against a registry root that has never
/// heard of it. This drives the attack first (a mint with no creation behind it, which must be
/// REFUSED), then the honest path (create, self-build the path, mint), so the gate is proven to
/// discriminate rather than to refuse everything.
#[test]
fn a_mint_for_an_asset_that_was_never_created_is_refused_and_the_registered_one_is_not() {
    let mut node = crate::node::Node::new(crate::node::tests::genesis_block()).unwrap();
    let c = a_token();
    let desc = c.descriptor();

    // ⛔ THE ATTACK: no creation was ever published, so the registry cannot hold this asset.
    assert!(
        !node.verify_token_membership(&desc, &[], &[]),
        "an asset with no creation behind it is NOT in an empty registry"
    );

    // THE HONEST PATH: the creation registers (the paid creation door that writes this is pinned by the §BR-14 pins
    // `br14_*`; this pin's subject is the registry gate the mint asks).
    node.register_dsol_asset(&desc);

    // The minter self-builds its path from the PUBLIC creation stream — no party serves it.
    let leaves = vec![crate::dsol::descriptor_leaf(&desc)];
    let (sibs, dirs) = crate::dsol::token_membership_path(&leaves, 0)
        .expect("a minter can build its own path from the public creation stream");
    assert!(
        node.verify_token_membership(&desc, &sibs, &dirs),
        "⛔ AND THE REGISTERED ASSET VERIFIES. If this fails the gate refuses everything, which is a \
         censor rather than a gate — the failure mode a refutation-only pin would have hidden."
    );

    // A DIFFERENT descriptor must not ride the same path: the node re-derives the leaf itself.
    let mut forged = desc.clone();
    forged.symbol = "FAKE".into();
    assert!(
        !node.verify_token_membership(&forged, &sibs, &dirs),
        "a forged descriptor yields a different leaf and cannot reuse an honest path"
    );
}

/// ⭐⭐⭐ THE REGISTRY SURVIVES A RESTART — A REGRESSION I INTRODUCED, PINNED.
///
/// ⛔ IT DID NOT. The registry was built fresh in `Node::new` and lived only in memory, so a node that
/// restarted came back holding an EMPTY registry. That alone was merely a gap — until the mint gate
/// above started asking the registry whether an asset exists. Then the two together meant a restarted
/// node refuses EVERY honest mint for every asset ever created, mesh-wide, the moment its operator
/// restarts the daemon. The snapshot now carries the accumulator's parts, and `from_parts` REFUSES a
/// set of peaks that does not describe its own count rather than repairing it.
///
/// This drives the real daemon path: export, restore into a process image that holds nothing, then ask
/// the restored node the exact question the mint gate asks.
#[test]
fn a_restarted_node_still_knows_which_assets_this_chain_registered() {
    let mut node = crate::node::Node::new(crate::node::tests::genesis_block()).unwrap();
    let c = a_token();
    let desc = c.descriptor();
    // setup: the registry holds the asset (the paid creation door is pinned by `br14_*`; the subject here is persistence)
    node.register_dsol_asset(&desc);
    let root_before = node.token_registry_root();
    let size_before = node.dsol_registry_size();
    let leaves = vec![crate::dsol::descriptor_leaf(&desc)];
    let (sibs, dirs) = crate::dsol::token_membership_path(&leaves, 0).expect("the minter's own path");
    assert!(node.verify_token_membership(&desc, &sibs, &dirs), "PRECONDITION: it verifies before");

    // THE RESTART: the same two calls the daemon makes across a process boundary.
    let snap = node.export_snapshot().expect("a node checkpoints");
    let mut fresh = crate::node::Node::new(crate::node::tests::genesis_block()).unwrap();
    assert_eq!(
        fresh.dsol_registry_size().0,
        0,
        "PRECONDITION: the fresh image holds nothing, so anything it knows came from the checkpoint"
    );
    assert!(fresh.restore_snapshot(snap), "the fresh node accepts its own checkpoint");

    assert_eq!(
        fresh.token_registry_root(),
        root_before,
        "⛔ THE RESTARTED NODE CAME BACK AT A DIFFERENT REGISTRY ROOT. It would answer membership \
         questions differently from every peer that did not restart."
    );
    assert_eq!(fresh.dsol_registry_size(), size_before, "count and peaks both survive");
    assert!(
        fresh.verify_token_membership(&desc, &sibs, &dirs),
        "⛔ AND THIS IS THE FUND DEFECT: the restarted node no longer recognises an asset this chain \
         created, so the mint gate refuses every honest mint for it until the operator re-syncs."
    );

    // The gate still DISCRIMINATES after the restart — a restored registry that verifies everything
    // would pass the assert above while admitting supply for assets that were never created.
    let mut forged = desc.clone();
    forged.symbol = "FAKE".into();
    assert!(
        !fresh.verify_token_membership(&forged, &sibs, &dirs),
        "a restored registry that accepts a forged descriptor is a censor's opposite: it admits \
         unregistered supply"
    );
}

fn a_token() -> AssetCreateTx {
    let mut c = AssetCreateTx {
        kind: AssetKind::Token,
        symbol: "GATE".into(),
        name: "Gate Token".into(),
        logo: [0u8; 32],
        bytecode: crate::dsol::compile(crate::dsol::DsolKind::Token, "GATE", "Gate Token").bytecode,
        creator: [0u8; 32],
        asset_id: [0u8; 32],
        fee: super::CreationFee::default(),
        art: Vec::new(),
        supply: None,
    };
    c.asset_id = c.derived_id();
    // §BR-14: a creation always carries its fee burn (a real carrier; the paid pins replace it with a funded leg).
    c.fee = super::fee_leg_carrier_only_for_test(&c, 0xa70);
    c
}

/// ⭐ THE OWN-TRANSACTION EMBARGO, MEASURED (2026-11-10; the rule is a19f584f's, 2026-11-07, and had no unit pin): a
/// creation a wallet asked THIS node to build stays out of this node's own blocks while the network has not echoed
/// it, so the block that first carries it never names the wallet's node; once another node names it
/// (`release_own_tx`, what the runtime calls when the transaction comes back from a peer), this node lays it like
/// any other and it applies on both nodes.
/// CALIBRATION: the same creation with the embargo off IS carried by the very next block (every other pin of this
/// module is that case), so a block that leaves it out here is the embargo's doing.
/// TWO-PARTY-REVIEWED: what is asserted is the registry on the producer AND on the peer fed only its blocks.
#[test]
fn a_wallets_creation_stays_out_of_its_own_nodes_blocks_until_the_network_echoes_it() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let empty = a.token_registry_root();
    let mut c = a_token();
    let ts = crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut c, 77, 5_000);
    crate::node::embargo_own_txs_for_test(true);
    assert!(matches!(a.publish_asset_create(&c), crate::node::AssetSpendOutcome::Published), "the paid creation publishes");
    crate::node::embargo_own_txs_for_test(false);
    let pooled = a
        .mempool()
        .all_tx_ids()
        .iter()
        .map(|id| crate::hash::Hash32(*id))
        .find(|id| {
            a.mempool().get(id).is_some_and(|t| {
                crate::chain_object::unframe(&t.blob).map(|(k, _)| k) == Some(crate::chain_object::Class::AssetCreate)
            })
        })
        .expect("PRECONDITION: A's pool holds the creation");
    // HELD: A's next blocks leave it out, and it stays pooled.
    let held = a
        .produce(ts + 500, crate::hash::Hash32::hash(b"embargo-fr-1"), crate::hash::Hash32::hash(b"embargo-mc-1"))
        .expect("A produces while the creation is held");
    assert!(!held.tx_ids.contains(&pooled), "⛔ A's own block carried a wallet's transaction the network had not echoed");
    assert!(matches!(b.ingest_block(held, ts + 500), crate::relay::RelayOutcome::Added(_)), "B grafts the block");
    let ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    assert!(a.mempool().contains(&pooled), "the held creation stays pooled");
    assert_eq!((a.token_registry_root(), b.token_registry_root()), (empty, empty), "and nothing applied on either node");
    // ECHOED: another node named it; A lays it in its next block and both registries move, to the same root.
    a.release_own_tx(&pooled);
    let carried = a
        .produce(ts + 500, crate::hash::Hash32::hash(b"embargo-fr-2"), crate::hash::Hash32::hash(b"embargo-mc-2"))
        .expect("A produces after the echo");
    assert!(carried.tx_ids.contains(&pooled), "⛔ after the echo A's block still left the creation out");
    assert!(matches!(b.ingest_block(carried, ts + 500), crate::relay::RelayOutcome::Added(_)), "B grafts the carrying block");
    crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    assert_ne!(a.token_registry_root(), empty, "the creation applied on A");
    assert_eq!(b.token_registry_root(), a.token_registry_root(), "and on B, to the same root");
}

/// ⭐⭐⭐ DB-200 — AN ASSET CREATION TRAVELS: A PUBLISHES, A PRODUCES, B GRAFTS, B'S REGISTRY MOVES.
///
/// THIS PIN REPLACES A TRIPWIRE THAT DID ITS JOB. DB-193's
/// `an_asset_cannot_be_created_at_all_so_it_cannot_travel_to_a_second_node` asserted the real
/// behaviour of the day — the creation REFUSED and nothing written on either node — and named its own
/// successor in its failure message: *"publish on A, produce ONE block on A, `b.ingest_block(blk)`,
/// and require `b.token_registry_root()` to move OFF empty and to EQUAL A's. B must never be handed
/// the descriptor."* DB-200 removed the USDm faucet bound that closed the class on every chain but
/// testnet, the tripwire went red exactly as designed, and this is the assertion it asked for.
///
/// ⛔ WHY B IS NEVER HANDED THE DESCRIPTOR. `two_nodes_applying_the_same_creation_reach_the_same_registry_root`
/// hands both nodes the same blob, so it proves DETERMINISM, not travel. A creation that registers
/// only on its creator is exactly the local-mutation class the cardinal forbids — *"SELF-VERIFICATION
/// IS NOT CONSENSUS: it decides whether a node ACCEPTS a transition, never whether it HAPPENED"* — and
/// it is the shape that paid a DEX maker's lot out twice. B learns of this asset from the BLOCK or
/// not at all.
#[test]
fn a_published_asset_creation_travels_to_a_second_node_in_a_block() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let empty = a.token_registry_root();
    assert_eq!(
        b.token_registry_root(),
        empty,
        "PRECONDITION: two fresh nodes agree on an empty registry"
    );

    let mut c = a_token();
    let ts = crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut c, 2, 5_000);
    let published = a.publish_asset_create(&c);
    assert!(
        matches!(published, crate::node::AssetSpendOutcome::Published),
        "⛔ A user still cannot create an asset — the admission door refused it. Outcome: {published:?}"
    );

    let blk = a
        .produce(ts + 500, crate::hash::Hash32::hash(b"db200-frontier"), crate::hash::Hash32::hash(b"db200-miner"))
        .expect("A produces the block carrying its own pooled creation");

    // B is told NOTHING but the block.
    let outcome = b.ingest_block(blk, ts + 500);
    assert!(
        matches!(outcome, crate::relay::RelayOutcome::Added(_)),
        "⛔ B refused the block carrying the creation — an asset that cannot ride a block cannot \
         exist for anyone but its creator. Outcome: {outcome:?}"
    );
    // §BR-14: the creation (and its fee burn) is decided at the carrying block's fold, on both nodes.
    crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);

    assert_ne!(
        b.token_registry_root(),
        empty,
        "⛔ B grafted the block and its token registry did not move — the creation rode the wire and \
         was not APPLIED, so B cannot verify a membership proof for this asset and every honest mint \
         into it is refused at B's door"
    );
    assert_eq!(
        b.token_registry_root(),
        a.token_registry_root(),
        "⛔ the two nodes disagree about which assets exist — divergence between honest nodes, which \
         may be tracked but never excused"
    );
}

/// ⭐⭐⭐ DB-201 — AN ASSET MINT TRAVELS: A MINTS ITS OWN ASSET, A PRODUCES, B GRAFTS, AND B'S
/// NOTE FRONTIER MOVES TO EQUAL A'S.
///
/// DB-200 opened the door; an open door is not a moved value. This carries a REAL mint the whole way
/// and asserts on the SECOND PARTY, which is the only thing that distinguishes a chain object from
/// the local mutation that paid a DEX maker's lot out twice.
///
/// ⛔ NOTHING HERE IS A FIXTURE SHORTCUT — each of the three gates the mint must pass is satisfied
/// the way a real minter satisfies it, because a mint that passes on stubs proves nothing:
///   • the CARRIER is a genuine WHIR proof from `prove_asset_mint_validity_bytes`, and the note's
///     commitment is written in the one canonical form `note_cm_of` reads, so `credit_is_authorised`
///     verifies the carrier against the note actually carried, at the amount actually claimed, under
///     THIS asset's tag;
///   • the SIGNATURE is a real ML-DSA-65 signature by the keypair whose `pubkey_id` the creation
///     derived its id from — `creator_authorised` rebuilds the descriptor from the mint's own pubkey
///     and refuses if it does not re-derive the claimed id, so no other key can mint this asset;
///   • the REGISTRY PATH is SELF-BUILT from the public creation stream (`token_membership_path`), not
///     served by any party — the liveness half of the trustless cardinal.
///
/// ⭐ AND B IS NEVER HANDED THE MINT. It sees the block. `b.note_frontier_root()` moving off its
/// pre-mint value and landing on A's is B having APPLIED the credit from block bytes alone — which
/// also exercises DB-165's rehydration, since `output_notes` no longer travel on the wire.
#[test]
fn a_published_asset_mint_travels_to_a_second_node_in_a_block() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());

    // THE CREATOR'S PQ IDENTITY. The asset id derives from `pubkey_id(&pk)`, so this keypair is the
    // only one that can ever mint this asset.
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    const SYMBOL: &str = "MINT";
    const NAME: &str = "DB-201 mint token";
    let mut c = AssetCreateTx {
        kind: AssetKind::Token,
        symbol: SYMBOL.to_string(),
        name: NAME.to_string(),
        logo: [0u8; 32],
        bytecode: crate::dsol::compile(crate::dsol::DsolKind::Token, SYMBOL, NAME).bytecode,
        creator: crate::pqauth::pubkey_id(&pk),
        asset_id: [0u8; 32],
        fee: super::CreationFee::default(),
        art: Vec::new(),
        supply: None,
    };
    c.asset_id = c.derived_id();
    // §BR-14: the creation pays its fee — a USDm note funded and folded on both nodes first.
    crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut c, 3, 1_000);

    // 1. THE CREATION RIDES A BLOCK TO B (DB-200) — the mint has nothing to be a member of otherwise.
    assert!(
        matches!(a.publish_asset_create(&c), crate::node::AssetSpendOutcome::Published),
        "PRECONDITION: the creation is admitted"
    );
    let blk1 = a
        .produce(5_000, crate::hash::Hash32::hash(b"db201-fr-1"), crate::hash::Hash32::hash(b"db201-mc-1"))
        .expect("A produces the block carrying the creation");
    assert!(
        matches!(b.ingest_block(blk1, 5_000), crate::relay::RelayOutcome::Added(_)),
        "PRECONDITION: B grafts the creation block"
    );
    // §BR-14: creation and mint are decided at the carrying block's fold, on both nodes.
    crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], 5_000, 100);
    assert_eq!(
        b.token_registry_root(),
        a.token_registry_root(),
        "PRECONDITION: B registered the asset from the block"
    );

    // 2. THE MINT, BUILT THE WAY A REAL MINTER BUILDS IT.
    const AMOUNT: u64 = 4_200;
    let note_sk: crate::spend_frontier::Digest4 =
        usdm_decider::poseidon2_compress::lanes_of_const(&[7, 7, 7, 7]);
    let (mint_carrier, cm) = usdm_decider::whir_rec_block::prove_asset_mint_validity_bytes(
        AMOUNT,
        c.asset_tag(),
        &note_sk,
    )
    .expect("a real WHIR mint carrier");
    let cm_bytes = crate::spend_frontier::leaf_to_cm_bytes(cm);
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..crate::spend_frontier::NOTE_CM_BYTES].copy_from_slice(&cm_bytes);

    // SELF-BUILT FROM THE PUBLIC CREATION STREAM — no party serves this.
    let desc = c.descriptor();
    let leaves = vec![crate::dsol::descriptor_leaf(&desc)];
    let (registry_path, registry_dirs) =
        crate::dsol::token_membership_path(&leaves, 0).expect("the minter's own path");

    let creator_sig =
        crate::pqauth::ml_dsa_sign(
            &crate::asset_tx::asset_mint_msg(
                &c.asset_id,
                AMOUNT,
                &cm_bytes,
                &crate::oli::owner_clue_digest(&[0x5a; crate::peg_in_tx::OWNER_CLUE_MAX]),
                "",
            ),
            &sk,
        )
            .expect("the creator signs its own mint");

    let m = AssetMintTx {
        asset_id: c.asset_id,
        kind: AssetKind::Token,
        amount: AMOUNT,
        note,
        mint_carrier,
        owner_clue: vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX],
        creator_pubkey: pk,
        creator_sig,
        symbol: SYMBOL.to_string(),
        asset_name: NAME.to_string(),
        registry_path,
        registry_dirs,
        logo: [0u8; 32],
        collection: String::new(),
    };

    // ⛔ THE NOTE FRONTIER IS THE WRONG OBSERVABLE HERE, AND FINDING THAT OUT IS WHY THIS PIN
    // ASSERTS ON THE NULLIFIER SIDE. `note_frontier_root()` advances only when a WHOLE 256-leaf
    // record folds (`record_note_payload_for` is the sole production appender), so one mint note
    // moves it on NEITHER node — measured: both roots identical before and after, on A as well as B.
    // Asserting it would have read as "the mint did not travel" when the mint travelled perfectly.
    //
    // What MUST move is the spent set. The mint retires the asset's ISSUANCE RIGHT
    // (`issue_right_nf(&asset_id)` rides the tx's nullifiers) — that is what makes an asset mintable
    // exactly once per right rather than repeatedly. So B, having seen nothing but the block, must
    // have absorbed that nullifier, and `nullifier_root()` is the A_tip fold over exactly that set.
    let b_nf_before = b.nullifier_root();
    let a_nf_before = a.nullifier_root();
    let published = a.publish_asset_mint(&m);
    assert!(
        matches!(published, crate::node::AssetSpendOutcome::Published),
        "⛔ a creator cannot mint supply of the asset it created. Outcome: {published:?}"
    );
    let blk2 = a
        .produce(6_000, crate::hash::Hash32::hash(b"db201-fr-2"), crate::hash::Hash32::hash(b"db201-mc-2"))
        .expect("A produces the block carrying its own mint");
    let outcome = b.ingest_block(blk2, 6_000);
    assert!(
        matches!(outcome, crate::relay::RelayOutcome::Added(_)),
        "⛔ B refused the block carrying the mint. Outcome: {outcome:?}"
    );
    // §BR-14: creation and mint are decided at the carrying block's fold, on both nodes.
    crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], 6_000, 100);

    assert_ne!(
        a.nullifier_root(),
        a_nf_before,
        "PRECONDITION: the mint retires the issuance right on its own producer — if this holds still, \
         the mint carried no nullifier and the assertion below would pass vacuously"
    );
    assert_ne!(
        b.nullifier_root(),
        b_nf_before,
        "⛔ B grafted the mint block and its SPENT SET did not move — the issuance right was not \
         retired on B, so B would admit this same mint again and the supply exists on its minter \
         alone. That is the local mutation the cardinal forbids."
    );
    assert_eq!(
        b.nullifier_root(),
        a.nullifier_root(),
        "⛔ the two nodes disagree about what has been spent — divergence between honest nodes, \
         which may be tracked but never excused"
    );
}

/// ⛔⛔⛔ ROGUE-ROLE CENSUS (2026-10-03) — A SECOND MINT OF ONE ASSET, CARRIED BY A ROGUE PRODUCER, CREDITS NOTHING.
///
/// A token "can be issued EXACTLY ONCE" (its issuance right). The real-node journey
/// `a_mint_admitted_by_one_real_process_retires_the_issuance_right_on_the_other` MEASURED a peer's POOL admitting a second
/// mint after the first had ridden a block ("PUBLISHED"). This pin asks the question that decides supply: when a block
/// CARRIES that second mint, does any node credit it?
/// - The second mint is fully valid: the creator's own signature, a real WHIR carrier for a new note.
/// - It rides a structurally whole block: the note is committed, the object is in carriage form, and the
///   issuance-right nullifier is in the lane with every root resealed.
/// - The peer must not hold the second note.
/// CONTROL: the peer holds the FIRST mint's note, so the read is not vacuous. Both nodes fold at the tip, so the fold's
/// verdict, not its absence, is what is measured.
/// TWO-PARTY-REVIEWED: A creates and mints; B is the rogue producer; A is the peer that judges B's block.
#[test]
fn a_second_mint_of_one_asset_carried_by_a_rogue_producer_credits_no_peer() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    const SYMBOL: &str = "TWICE";
    const NAME: &str = "census second-mint token";
    let mut c = AssetCreateTx {
        kind: AssetKind::Token,
        symbol: SYMBOL.to_string(),
        name: NAME.to_string(),
        logo: [0u8; 32],
        bytecode: crate::dsol::compile(crate::dsol::DsolKind::Token, SYMBOL, NAME).bytecode,
        creator: crate::pqauth::pubkey_id(&pk),
        asset_id: [0u8; 32],
        fee: super::CreationFee::default(),
        art: Vec::new(),
        supply: None,
    };
    c.asset_id = c.derived_id();
    // §BR-14: the creation pays its fee — a USDm note funded and folded on both nodes first.
    crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut c, 4, 1_000);
    assert!(matches!(a.publish_asset_create(&c), crate::node::AssetSpendOutcome::Published), "the creation is admitted");
    let blk1 = a.produce(5_000, crate::hash::Hash32::hash(b"twice-fr-1"), crate::hash::Hash32::hash(b"twice-mc-1")).expect("creation block");
    assert!(matches!(b.ingest_block(blk1, 5_000), crate::relay::RelayOutcome::Added(_)), "B grafts the creation");
    // §BR-14: creation and mint are decided at the carrying block's fold, on both nodes.
    crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], 5_000, 100);
    let desc = c.descriptor();
    let (registry_path, registry_dirs) =
        crate::dsol::token_membership_path(&[crate::dsol::descriptor_leaf(&desc)], 0).expect("the minter's own path");
    let clue = vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX];
    let mint_of = |amount: u64, seed: u64| -> AssetMintTx {
        let note_sk = usdm_decider::poseidon2_compress::lanes_of(&[seed, seed, seed, seed]);
        let (mint_carrier, cm) =
            usdm_decider::whir_rec_block::prove_asset_mint_validity_bytes(amount, c.asset_tag(), &note_sk).expect("a real WHIR mint carrier");
        let cm_bytes = crate::spend_frontier::leaf_to_cm_bytes(cm);
        let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        note[..crate::spend_frontier::NOTE_CM_BYTES].copy_from_slice(&cm_bytes);
        let creator_sig = crate::pqauth::ml_dsa_sign(
            &crate::asset_tx::asset_mint_msg(&c.asset_id, amount, &cm_bytes, &crate::oli::owner_clue_digest(&clue), ""),
            &sk,
        )
        .expect("the creator signs");
        AssetMintTx {
            asset_id: c.asset_id,
            kind: AssetKind::Token,
            amount,
            note,
            mint_carrier,
            owner_clue: clue.clone(),
            creator_pubkey: pk.clone(),
            creator_sig,
            symbol: SYMBOL.to_string(),
            asset_name: NAME.to_string(),
            registry_path: registry_path.clone(),
            registry_dirs: registry_dirs.clone(),
            logo: [0u8; 32],
            collection: String::new(),
        }
    };
    // THE FIRST MINT, through A's own door, to B in a block.
    let first = mint_of(4_200, 7);
    assert!(matches!(a.publish_asset_mint(&first), crate::node::AssetSpendOutcome::Published), "the first mint publishes");
    let blk2 = a.produce(6_000, crate::hash::Hash32::hash(b"twice-fr-2"), crate::hash::Hash32::hash(b"twice-mc-2")).expect("mint block");
    assert!(matches!(b.ingest_block(blk2, 6_000), crate::relay::RelayOutcome::Added(_)), "B grafts the first mint");
    // §BR-14: creation and mint are decided at the carrying block's fold, on both nodes.
    crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], 6_000, 100);
    let first_cm = <[u8; 32]>::try_from(&first.note[..32]).expect("cm");
    assert!(
        a.holds_record_with_cm(&first_cm) && b.holds_record_with_cm(&first_cm),
        "CONTROL: both nodes hold the FIRST mint's note — the read below is not vacuous"
    );
    // THE SECOND MINT: valid in every field a blob-only door can check — and its issuance right is already retired.
    let second = mint_of(9_999_999, 8);
    assert!(
        crate::chain_object::admissible(&second.wire(), a.params().order_fill_fee_bps, a.params().genesis_mint_allowance(), false),
        "CALIBRATION: the second mint is admissible on its own bytes — the attack is armed"
    );
    // THE PUBLISHER DOOR on BOTH nodes: the right is retired on each one's canonical state, so each refuses the second
    // mint before pooling it (the real-node journey MEASURED the peer's route answering "PUBLISHED" here).
    let spent_on = |n: &crate::node::Node| n.sparse_spent_verdict(&super::issue_right_nf(&c.asset_id));
    eprintln!("[rogue-mint] the issuance right's spent verdict — A: {:?}, B: {:?}", spent_on(&a), spent_on(&b));
    for (who, n) in [("A (the minter)", &mut a), ("B (the peer)", &mut b)] {
        let out = n.publish_asset_mint(&second);
        assert!(
            matches!(out, crate::node::AssetSpendOutcome::Refused(_)),
            "⛔ {who}'s publisher admitted a SECOND mint of an asset whose issuance right is retired on its own chain: {out:?}"
        );
    }
    let mut rogue = b.produce(7_000, crate::hash::Hash32::hash(b"twice-rogue"), crate::hash::Hash32::hash(b"twice-rogue-m")).expect("B lays a block");
    rogue.output_notes = second.note.clone();
    rogue.header.output_notes_root = crate::block::da_notes_root_of(&rogue.output_notes);
    rogue.note_commitments = b.note_commitment_carrier_for_test(&rogue.output_notes);
    rogue.header.note_commitments_root = crate::hash::Hash32::hash(&rogue.note_commitments);
    (rogue.credit_set, rogue.wide_objects) = crate::block::seal_carriages(&[crate::chain_object::carriage_of(&second.wire()).expect("carriage")], &crate::block::credit_seal_key(&rogue.header, rogue.cover_key.as_ref()).expect("the fixture block carries its cover key")).expect("the fixture's objects fit the sealed width");
    rogue.header.credit_set_root = crate::block::credit_set_root_of(&rogue.credit_set);
    rogue.nullifier_proof.padded_tags.push(super::issue_right_nf(&c.asset_id));
    rogue.header.nullifier_tags_root = crate::block::nullifier_tags_root_of(&rogue.nullifier_proof.padded_tags);
    crate::node::tests::lay_tag_evidence_for_test(&b, &mut rogue, &[super::issue_right_nf(&c.asset_id)]);
    let out = a.ingest_block_preverified(rogue, 7_500);
    eprintln!("[rogue-mint] A's outcome for a block carrying a SECOND mint of one asset: {out:?}");
    assert!(matches!(out, crate::relay::RelayOutcome::Added(_)), "CALIBRATION: the rogue block passes the structural doors: {out:?}");
    let second_cm = <[u8; 32]>::try_from(&second.note[..32]).expect("cm");
    assert!(
        !a.holds_record_with_cm(&second_cm),
        "⛔⛔⛔ ROGUE PRODUCER: a peer credited a SECOND mint of an asset whose issuance right was already retired — supply \
         minted twice"
    );
}

/// ⭐⭐⭐ DB-216 — AN ASSET TRANSFER TRAVELS TO A SECOND NODE, AND A SECOND SPEND OF THE SAME NOTE IS
/// REFUSED THERE. The `AssetSpend` row of the value-class register (criterion 1).
///
/// DB-201 left the state this needs on both nodes — a created asset and a minted note — so this carries
/// the NEXT hop the same way: A publishes a transfer of the minted note, produces, B grafts the block,
/// and every assertion is on B's OWN state:
///   * B's spent set moved and agrees with A's (the burn travelled, it was not a local mutation);
///   * B's record for the transfer block holds BOTH output notes (the credit travelled);
///   * a DIFFERENT transfer of the SAME note — new outputs, new bytes, same nullifier — is refused on B
///     and on A. Identical bytes would be refused by the settled-object set alone and would prove
///     nothing about the note; different bytes can only be refused by the spent set.
///
/// Both carriers are REAL: the validity carrier over the minted note's own opening, and the one-step
/// membership carrier built from the record B derived from the block, bound together by
/// `leaf_commit = compress(leaf, nullifier)`.
#[test]
fn a_published_asset_transfer_travels_to_a_second_node_and_a_second_spend_is_refused() {
    use usdm_decider::note_membership_air::NoteMembershipCarrier;
    use usdm_decider::whir_rec_block::{
        asset_spend_input_leaf, prove_asset_spend_validity_carrier_bytes, AssetSpendValidityWitness,
    };
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());

    // ── 1. CREATE (DB-200), the same way DB-201 does.
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    const SYMBOL: &str = "XFER";
    const NAME: &str = "DB-216 transfer token";
    let mut c = AssetCreateTx {
        kind: AssetKind::Token,
        symbol: SYMBOL.to_string(),
        name: NAME.to_string(),
        logo: [0u8; 32],
        bytecode: crate::dsol::compile(crate::dsol::DsolKind::Token, SYMBOL, NAME).bytecode,
        creator: crate::pqauth::pubkey_id(&pk),
        asset_id: [0u8; 32],
        fee: super::CreationFee::default(),
        art: Vec::new(),
        supply: None,
    };
    c.asset_id = c.derived_id();
    // §BR-14: the creation pays its fee — a USDm note funded and folded on both nodes first.
    crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut c, 5, 1_000);
    assert!(
        matches!(a.publish_asset_create(&c), crate::node::AssetSpendOutcome::Published),
        "PRECONDITION: the creation is admitted"
    );
    let blk1 = a
        .produce(5_000, crate::hash::Hash32::hash(b"db216-fr-1"), crate::hash::Hash32::hash(b"db216-mc-1"))
        .expect("A produces the creation block");
    assert!(
        matches!(b.ingest_block(blk1, 5_000), crate::relay::RelayOutcome::Added(_)),
        "PRECONDITION: B grafts the creation block"
    );
    // §BR-14: creation and mint are decided at the carrying block's fold, on both nodes.
    crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], 5_000, 100);

    // ── 2. MINT (DB-201) — a real WHIR carrier over the spender's OPENING (DB-395: the spender below is its owner).
    const AMOUNT: u64 = 4_200;
    let note_sk_owner =
        usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of_const(&[216, 216, 216, 216]));
    let note_sk = note_sk_owner.opening();
    let (mint_carrier, cm) =
        usdm_decider::whir_rec_block::prove_asset_mint_validity_bytes(AMOUNT, c.asset_tag(), &note_sk)
            .expect("a real WHIR mint carrier");
    let cm_bytes = crate::spend_frontier::leaf_to_cm_bytes(cm);
    let note_of = |cm: crate::spend_frontier::Digest4| -> Vec<u8> {
        let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        n[..crate::spend_frontier::NOTE_CM_BYTES]
            .copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
        n
    };
    let desc = c.descriptor();
    let leaves = vec![crate::dsol::descriptor_leaf(&desc)];
    let (registry_path, registry_dirs) =
        crate::dsol::token_membership_path(&leaves, 0).expect("the minter's own path");
    let creator_sig =
        crate::pqauth::ml_dsa_sign(
            &crate::asset_tx::asset_mint_msg(
                &c.asset_id,
                AMOUNT,
                &cm_bytes,
                &crate::oli::owner_clue_digest(&[0x5a; crate::peg_in_tx::OWNER_CLUE_MAX]),
                "",
            ),
            &sk,
        )
            .expect("the creator signs its own mint");
    let m = AssetMintTx {
        asset_id: c.asset_id,
        kind: AssetKind::Token,
        amount: AMOUNT,
        note: note_of(cm),
        mint_carrier,
        owner_clue: vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX],
        creator_pubkey: pk,
        creator_sig,
        symbol: SYMBOL.to_string(),
        asset_name: NAME.to_string(),
        registry_path,
        registry_dirs,
        logo: [0u8; 32],
        collection: String::new(),
    };
    assert!(
        matches!(a.publish_asset_mint(&m), crate::node::AssetSpendOutcome::Published),
        "PRECONDITION: the creator mints"
    );
    let blk2 = a
        .produce(6_000, crate::hash::Hash32::hash(b"db216-fr-2"), crate::hash::Hash32::hash(b"db216-mc-2"))
        .expect("A produces the mint block");
    let blk2_id = blk2.id();
    assert!(
        matches!(b.ingest_block(blk2, 6_000), crate::relay::RelayOutcome::Added(_)),
        "PRECONDITION: B grafts the mint block"
    );
    // DB-358 (1) (and §BR-14: the mint is decided at its block's fold): the transfer spends the minted note, so the fold passes the mint block first (a wallet waits the
    // same way). Idle blocks at 20 ms steps stay below the transfer block's 7,000.
    crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], 6_000, 20);

    // ── 3. THE MINTED NOTE, AS B DERIVES IT FROM THE BLOCK ALONE.
    let rid = crate::node::Node::da_record_id_for_block(&blk2_id, 0);
    let want_leaf = crate::spend_frontier::note_leaf_of(&cm_bytes);
    let rec = b
        .da_block_leaves(rid)
        .expect("⛔ B holds no record for the mint block — the minted note cannot be proven a member anywhere but its minter");
    let slot = rec
        .iter()
        .position(|l| *l == want_leaf)
        .expect("⛔ the minted note is not in its own block's record on B — a mint that credits no leaf is unspendable")
        as u8;
    let (sibs, dirs, root) = b
        .da_note_copath_in_block(rid, slot)
        .expect("B serves the in-record copath from the record alone");

    // ── 4. THE TRANSFER: 1,500 to a recipient, the rest back as change, one asset throughout.
    let witness = |out0: u64| AssetSpendValidityWitness {
        value_in: AMOUNT,
        owner: note_sk_owner,
        value_out: AMOUNT,
        fee: 0,
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
        out0_value: out0,
        out0_opening: usdm_decider::poseidon2_compress::lanes_of_const(&[31, 41, 59, 26]),
        out1_value: AMOUNT - out0,
        out1_opening: usdm_decider::poseidon2_compress::lanes_of_const(&[27, 18, 28, 18]),
        asset: c.asset_tag(),
    };
    // §19: the member leg (carrier + tuple) with ZERO outputs, built ONCE for the input note — the validity carrier
    // binds each build's outputs; hoisted so the builds below do not hold `a` while `a` executes them
    let (leg_carrier, leg_tuple) = {
        let w = witness(1_500);
        let (_, _, nf, _) = prove_asset_spend_validity_carrier_bytes(&w).expect("an honest transfer proves");
        a.member_leg_for_test(
            &crate::spend_frontier::leaf_to_cm_bytes(want_leaf),
            nf,
            crate::spend_frontier::TEST_LC_BLIND,
            &[0u8; 32],
            &[0u8; 32],
        )
        .expect("A's member book holds the minted note's path: the member leg builds")
    };
    let mut leg_tuple_bytes = Vec::with_capacity(crate::member_transition::MEMBER_TUPLE_BYTES);
    crate::member_transition::write_tuple(&leg_tuple, &mut leg_tuple_bytes);
    let build = |out0: u64| -> AssetSpendTx {
        let w = witness(out0);
        assert_eq!(
            asset_spend_input_leaf(&w).expect("the input opens"),
            want_leaf,
            "⛔ THE TRANSFER'S INPUT LEAF IS NOT THE MINTED NOTE'S LEAF — mint and spend disagree on the \
             note's identity, so no minted asset could ever be moved"
        );
        let (validity_carrier, cms, nf, lc) =
            prove_asset_spend_validity_carrier_bytes(&w).expect("an honest transfer proves");
        AssetSpendTx {
            notes: [note_of(cms[0]), note_of(cms[1])],
            nullifier: crate::spend_frontier::leaf_to_cm_bytes(nf),
            leaf_commit: lc,
            validity_carrier,
            membership_carrier: leg_carrier.clone(),
            member_tuple: leg_tuple_bytes.clone(),
            named_record: 0,
            tip_prev: Default::default(),
            tip_root: Default::default(),
            tip_acc: Default::default(),
            owner_clues: vec![vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX]; crate::asset_tx::ASSET_SPEND_OUTPUTS],
            slot_tag: None,
        }
    };
    let t = build(1_500);
    let cms = t.output_commitments().expect("canonical output fronts");
    // §19 TAMPER: a member leg whose tuple is cut short names no spend — refused before any proof work, on both.
    {
        let mut cut = t.clone();
        cut.member_tuple.truncate(cut.member_tuple.len() / 2);
        assert!(
            !matches!(a.execute_asset_spend(&cut), crate::node::AssetSpendOutcome::Published),
            "⛔ §19: the asset door admitted a spend whose member tuple is malformed"
        );
        assert!(
            !matches!(b.execute_asset_spend(&cut), crate::node::AssetSpendOutcome::Published),
            "⛔ §19: the peer's asset door admitted a spend whose member tuple is malformed"
        );
    }

    // ── 5. PUBLISH ON A, PRODUCE, B GRAFTS.
    let (a_nf_before, b_nf_before) = (a.nullifier_root(), b.nullifier_root());
    let published = a.execute_asset_spend(&t);
    assert!(
        matches!(published, crate::node::AssetSpendOutcome::Published),
        "⛔ a holder cannot transfer an asset it was minted. Outcome: {published:?}"
    );
    let blk3 = a
        .produce(7_000, crate::hash::Hash32::hash(b"db216-fr-3"), crate::hash::Hash32::hash(b"db216-mc-3"))
        .expect("A produces the transfer block");
    let blk3_id = blk3.id();
    let outcome = b.ingest_block(blk3, 7_000);
    assert!(
        matches!(outcome, crate::relay::RelayOutcome::Added(_)),
        "⛔ B refused the block carrying the transfer. Outcome: {outcome:?}"
    );

    // ── 6. ON B'S OWN STATE: the burn travelled…
    assert_ne!(
        a.nullifier_root(),
        a_nf_before,
        "PRECONDITION: the transfer retired its input on its own publisher — otherwise the next \
         assertion would pass vacuously"
    );
    assert_ne!(
        b.nullifier_root(),
        b_nf_before,
        "⛔ B grafted the transfer and its SPENT SET did not move — the input is live on B and would be \
         spent again there"
    );
    assert_eq!(b.nullifier_root(), a.nullifier_root(), "⛔ the two nodes disagree about what is spent");
    // …and so did the credit.
    let rid3 = crate::node::Node::da_record_id_for_block(&blk3_id, 0);
    let rec3 = b.da_block_leaves(rid3).expect("⛔ B holds no record for the transfer block");
    for (i, out) in cms.iter().enumerate() {
        let leaf = crate::spend_frontier::note_leaf_of(&crate::spend_frontier::leaf_to_cm_bytes(*out));
        assert!(
            rec3.contains(&leaf),
            "⛔ output {i} of the transfer is not in B's record — the recipient was paid on A only"
        );
    }

    // ── 7. A SECOND SPEND OF THE SAME NOTE — different outputs, different bytes, SAME nullifier.
    let t2 = build(2_000);
    assert_ne!(t2.wire(), t.wire(), "PRECONDITION: the second spend is a different object");
    assert_eq!(t2.nullifier, t.nullifier, "PRECONDITION: …of the same note");
    let on_b = b.execute_asset_spend(&t2);
    assert!(
        !matches!(on_b, crate::node::AssetSpendOutcome::Published),
        "⛔⛔⛔ B ADMITTED A SECOND SPEND OF A NOTE IT HAD ALREADY SEEN SPENT IN A BLOCK. Outcome: {on_b:?}"
    );
    let on_a = a.execute_asset_spend(&t2);
    assert!(
        !matches!(on_a, crate::node::AssetSpendOutcome::Published),
        "⛔⛔⛔ A ADMITTED A SECOND SPEND OF A NOTE IT SPENT ITSELF. Outcome: {on_a:?}"
    );
}

/// ⭐ AN ID IS RECOMPUTED, NEVER TRUSTED. Claiming another asset's identity is how you mint into it.
#[test]
fn a_creation_whose_id_does_not_match_its_own_descriptor_is_refused() {
    let good = a_token();
    assert!(AssetCreateTx::decode(&good.encode()).is_some(), "an honest creation decodes");
    let mut forged = good.clone();
    forged.symbol = "OTHER".into(); // keeps the id of GATE while describing a different asset
    assert!(
        AssetCreateTx::decode(&forged.encode()).is_none(),
        "⛔ a descriptor kept another asset's id and was accepted — that is identity theft at the \
         asset layer, and every mint into it would be a mint into somebody else's supply"
    );
}

/// Two creators may pick the same ticker. They are still different assets, because the tag comes from
/// the id and the id comes from the whole descriptor.
#[test]
fn the_same_symbol_from_two_creators_is_two_different_assets() {
    let a = a_token();
    let mut b = AssetCreateTx { name: "Gate Token II".into(), ..a.clone() };
    b.asset_id = b.derived_id();
    assert_ne!(a.asset_id, b.asset_id, "different descriptors, different ids");
    assert_ne!(a.asset_tag(), b.asset_tag(), "different ids, different note tags");
}

/// ⭐ AN NFT IS ONE THING. Quantity five would make it a token with a confusing name, and every surface
/// treating it as unique would be wrong about it.
#[test]
fn an_nft_mint_of_more_than_one_is_refused() {
    let mk = |kind, amount| AssetMintTx {
        asset_id: [7u8; 32],
        kind,
        amount,
        note: vec![9u8; crate::cover::PQ_NOTE_BYTES],
        mint_carrier: vec![1u8; 64],
        owner_clue: vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX],
        creator_pubkey: vec![1u8; 8],
        creator_sig: vec![2u8; 8],
        symbol: String::new(),
        asset_name: String::new(),
        registry_path: Vec::new(),
        registry_dirs: Vec::new(),
        logo: [0u8; 32],
        collection: String::new(),
    };
    assert!(AssetMintTx::decode(&mk(AssetKind::Nft, 1).encode()).is_some(), "one NFT is an NFT");
    assert!(
        AssetMintTx::decode(&mk(AssetKind::Nft, 5).encode()).is_none(),
        "⛔ a five-unit NFT was accepted — an NFT must be indivisible or it is simply a token"
    );
    assert!(AssetMintTx::decode(&mk(AssetKind::Token, 5).encode()).is_some(), "a token may be divisible");
    assert!(AssetMintTx::decode(&mk(AssetKind::Token, 0).encode()).is_none(), "a zero mint is not a mint");
}

/// ⭐ THE GATE THAT STOPS THE CALLER CHOOSING WHAT IT RECEIVES. A mint whose carrier does not open the
/// note to THIS amount in THIS asset credits nothing — the peg hole of 2026-08-26, one asset layer up.
#[test]
fn a_mint_whose_carrier_does_not_open_the_note_is_not_authorised() {
    let m = AssetMintTx {
        asset_id: [3u8; 32],
        kind: AssetKind::Token,
        amount: 1_000_000,
        note: vec![4u8; crate::cover::PQ_NOTE_BYTES],
        mint_carrier: vec![0xAB; 96], // not a proof of anything
        owner_clue: vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX],
        creator_pubkey: vec![1u8; 8],
        creator_sig: vec![2u8; 8],
        symbol: String::new(),
        asset_name: String::new(),
        registry_path: Vec::new(),
        registry_dirs: Vec::new(),
        logo: [0u8; 32],
        collection: String::new(),
    };
    assert!(
        !m.credit_is_authorised(),
        "⛔ a mint with a garbage carrier was authorised — then the caller picks its own amount"
    );
}

/// ⭐ RED-TEAM HOLE-CLOSURE PIN (2026-09-06) — WIRE MALLEABILITY, creation class: one descriptor
/// under MANY distinct byte encodings blinds the pool's by-id dedup even though every copy is the
/// SAME creation.
///
/// ROOT-LAYER: `AssetCreateTx::decode` — `postcard::from_bytes` deserializes a prefix and IGNORES
/// trailing bytes, so `encode(a) || junk` decodes to the SAME descriptor while `PqTx::content_id`
/// (blake3 of the whole blob) names a DIFFERENT transaction; one creation could occupy unbounded
/// pool slots. The fix is the shared strict full-consumption decode (`chain_object::decode_exact`).
/// MEASURED: 7 trailing bytes appended after the postcard payload; the padded bytes differ from
/// the canonical encoding and MUST refuse to decode. First run 2026-09-06 decides RED or GREEN — a
/// RED is the confirmed malleability hole and this pin specifies the decode-strictness fix.
/// MUST-STAY-GREEN: a creation carrying trailing bytes is not an asset creation.
#[test]
fn a_creation_with_trailing_bytes_is_not_a_second_creation() {
    let c = a_token();
    let canonical = c.encode();
    assert!(AssetCreateTx::decode(&canonical).is_some(), "PRECONDITION: the canonical bytes decode");
    let mut padded = canonical.clone();
    padded.extend_from_slice(&[0xEE; 7]);
    assert_ne!(padded, canonical, "the padded bytes are genuinely different bytes");
    assert!(
        AssetCreateTx::decode(&padded).is_none(),
        "FORGERY: the same creation under a second byte encoding must be refused — one object, ONE \
         encoding; a tolerated tail gives one descriptor unbounded distinct content ids"
    );
}

/// ⭐ RED-TEAM HOLE-CLOSURE PIN (2026-09-06) — WIRE MALLEABILITY, mint class: the SUPPLY-BEARING
/// sibling of the creation pin above — a padded re-encoding of one mint is the measured inflation
/// class (one credit riding several block carriages) if the door tolerates it.
///
/// ROOT-LAYER: `AssetMintTx::decode` — same prefix-tolerant `postcard::from_bytes` shape, fixed by
/// the same shared strict decode (`chain_object::decode_exact`).
/// MEASURED: 7 trailing bytes appended after the postcard payload; the padded bytes MUST refuse to
/// decode. First run 2026-09-06 decides RED or GREEN — RED is the confirmed hole; this pin is the
/// fix's specification.
/// MUST-STAY-GREEN: a mint carrying trailing bytes is not an asset mint.
#[test]
fn a_mint_with_trailing_bytes_is_not_a_second_mint() {
    let m = AssetMintTx {
        asset_id: [7u8; 32],
        kind: AssetKind::Token,
        amount: 5,
        note: vec![9u8; crate::cover::PQ_NOTE_BYTES],
        mint_carrier: vec![1u8; 64],
        owner_clue: vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX],
        creator_pubkey: vec![1u8; 8],
        creator_sig: vec![2u8; 8],
        symbol: String::new(),
        asset_name: String::new(),
        registry_path: Vec::new(),
        registry_dirs: Vec::new(),
        logo: [0u8; 32],
        collection: String::new(),
    };
    let canonical = m.encode();
    assert!(AssetMintTx::decode(&canonical).is_some(), "PRECONDITION: the canonical bytes decode");
    let mut padded = canonical.clone();
    padded.extend_from_slice(&[0xEE; 7]);
    assert_ne!(padded, canonical, "the padded bytes are genuinely different bytes");
    assert!(
        AssetMintTx::decode(&padded).is_none(),
        "FORGERY: the same mint under a second byte encoding must be refused — a tolerated tail lets \
         one issuance occupy unbounded pool slots and ride more than one block carriage"
    );
}

/// One asset object, one encoding: two nodes handed the same creation must agree on its bytes.
#[test]
fn an_asset_object_has_exactly_one_encoding() {
    let c = a_token();
    assert_eq!(c.encode(), c.encode(), "encoding must be deterministic");
    let back = AssetCreateTx::decode(&c.encode()).expect("round trips");
    assert_eq!(back.encode(), c.encode(), "encode(decode(x)) != x");
    assert_eq!(back.asset_tag(), c.asset_tag(), "the tag survives the round trip");
}

use super::{AssetSpendTx, ASSET_SPEND_CARRIER_BYTES_MAX, ASSET_SPEND_OUTPUTS};

/// A REAL asset transfer carrier, and the note payloads whose first bytes ARE its output
/// commitments. Everything a transfer needs except the membership half.
fn a_transfer() -> AssetSpendTx {
    let w = usdm_decider::whir_rec_block::AssetSpendValidityWitness {
        value_in: 1_000,
        owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[11, 22, 33, 44])),
        value_out: 1_000,
        fee: 0,
        lc_blind: crate::spend_frontier::TEST_LC_BLIND,
        out0_value: 400,
        out0_opening: usdm_decider::poseidon2_compress::lanes_of(&[55, 66, 77, 88]),
        out1_value: 600,
        out1_opening: usdm_decider::poseidon2_compress::lanes_of(&[99, 111, 122, 133]),
        asset: usdm_decider::whir_rec_block::wrapped_asset_tag(&[7u8; 32]),
    };
    let (carrier, cms, nf, lc) =
        usdm_decider::whir_rec_block::prove_asset_spend_validity_carrier_bytes(&w)
            .expect("an honest transfer proves");
    // A note whose front IS the commitment in the one production encoding (`leaf_to_cm_bytes`, as
    // the faucet, the book and the fill write it), padded to a real note's width — the commitment is
    // READ off the note, never declared beside it.
    let note_of = |cm: usdm_decider::poseidon2_compress::Digest| -> Vec<u8> {
        let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        n[..crate::spend_frontier::NOTE_CM_BYTES]
            .copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
        n
    };
    AssetSpendTx {
        notes: [note_of(cms[0]), note_of(cms[1])],
        nullifier: crate::spend_frontier::leaf_to_cm_bytes(nf),
        leaf_commit: lc,
        validity_carrier: carrier,
        membership_carrier: vec![1u8; 64], // a carrier that exists but attests nothing
        member_tuple: Vec::new(),
        named_record: 0,
        tip_prev: usdm_decider::poseidon2_compress::zero_digest(),
        tip_root: usdm_decider::poseidon2_compress::zero_digest(),
        tip_acc: usdm_decider::poseidon2_compress::zero_digest(),
        owner_clues: vec![vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX]; ASSET_SPEND_OUTPUTS],
        slot_tag: None,
    }
}

/// ⛔⛔⛔ DB-223 Q7 — A PEER MUST NOT CREDIT A WRAPPED / TOKEN / NFT TRANSFER WHOSE INPUT NEVER EXISTED.
/// The transfer's validity carrier conserves value in one asset, and its membership carrier attests NOTHING (the
/// note it spends was never received anywhere). A rogue producer pools it past its own door and lays the block; the
/// peer — fed only the block, folding at the tip — must not hold its outputs. READ before this pin: the graft door
/// justified a transfer's outputs on `admissible` (= conservation alone) and ran the membership verdict afterwards in
/// `apply_chain_asset_spend`, whose refusal stripped nothing; the class now decides at the FOLD (`is_fold_applied_class`)
/// and a refused transfer's outputs leave the row.
#[test]
fn a_peer_does_not_credit_an_asset_transfer_whose_input_never_existed() {
    let genesis = crate::node::tests::genesis_block();
    let mut a = crate::node::Node::new(genesis.clone()).unwrap();
    let mut node_b = crate::node::Node::new_folding_at_tip_for_test(genesis).unwrap();
    let t = a_transfer();
    assert!(t.value_is_conserved(), "CALIBRATION: the forged transfer conserves value — only its input is fake");
    let blob = t.wire();
    let tx_id = crate::mempool::PqTx::content_id(&blob);
    let burns = crate::cover::pad_tx_nullifiers_to_fixed(&[t.nullifier], tx_id.as_bytes()).expect("the lane pads");
    let mut out_notes = Vec::new();
    for n in t.notes.iter() {
        out_notes.extend_from_slice(n);
    }
    let mut tx = crate::mempool::PqTx {
        clock_ms: 0,
        id: tx_id,
        blob: blob.clone(),
        weight: blob.len() as u32,
        nullifiers: burns.iter().map(|n| crate::hash::Hash32(*n)).collect(),
        pow_stamp: 0,
        note_clues: Vec::new(),
        account_targets: Vec::new(),
        output_notes: out_notes,
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
    let need = a.mempool().required_stamp_bits();
    let mut ground = false;
    for stamp in 0..1u64 << 24 {
        tx.pow_stamp = stamp;
        if tx.stamp_work() >= need {
            ground = true;
            break;
        }
    }
    assert!(ground, "PRECONDITION: the stamp grinds");
    a.ingest_tx_unverified(tx).expect("the rogue producer pools its own forged transfer past its door");
    let blk = a
        .produce(5_000, crate::hash::Hash32::hash(b"db223-asset-fr"), crate::hash::Hash32::hash(b"db223-asset-mc"))
        .expect("A lays the block");
    let out_cm: [u8; 32] = t.notes[0][..32].try_into().expect("32 bytes");
    assert!(
        blk.output_notes.chunks(crate::cover::PQ_NOTE_BYTES).any(|n| n.len() >= 32 && n[..32] == out_cm),
        "CALIBRATION: the block carries the forged transfer's output — otherwise this proves nothing about the peer"
    );
    let outcome = node_b.ingest_block(blk, 9_000);
    eprintln!("[db223-asset] peer outcome for the block carrying a forged asset transfer: {outcome:?}");
    assert!(
        matches!(outcome, crate::relay::RelayOutcome::Added(_)),
        "CALIBRATION: the peer accepts the block (the refusal is the transfer's, never the block's): {outcome:?}"
    );
    assert!(
        !node_b.holds_record_with_cm(&out_cm),
        "⛔⛔⛔ DB-223 Q7: the peer holds the output of an asset transfer whose input never existed — a wrapped asset, \
         token or NFT minted from nothing"
    );
}

/// ⭐⭐⭐ THE TRANSFER EXISTS AND CONSERVES VALUE — the thing that was missing entirely. Before this,
/// `AssetApply` had CREATE and MINT only and the asset-spend carrier had ZERO callers: a holder could
/// be credited a token or an NFT and could never move it.
#[test]
fn an_asset_transfer_round_trips_and_conserves_value_in_one_asset() {
    let t = a_transfer();
    let wire = t.wire();
    let (class, payload) = crate::chain_object::unframe(&wire).expect("a framed transfer");
    assert_eq!(class, crate::chain_object::Class::AssetSpend);
    let back = AssetSpendTx::decode(payload).expect("an honest transfer decodes");
    assert_eq!(back, t, "the wire round trip is the identity");
    assert!(
        back.value_is_conserved(),
        "⛔ an honest transfer's carrier must verify against the commitments read off its OWN notes"
    );
    // The block carries exactly these two notes, in the carrier's order.
    assert_eq!(
        crate::chain_object::carried_note_payloads(&wire).expect("justified notes"),
        t.notes.to_vec(),
        "the wrapper may carry the object's own outputs and nothing else"
    );
}

/// ⛔ ONE CARRIER IS NEVER ENOUGH, AND THE STRUCTURAL DOOR SAYS SO FIRST.
/// The validity carrier proves conservation and one asset; it proves NOTHING about whether the spent
/// note was ever received, because its membership copath is a free witness (MEASURED in
/// `whir_rec_block::the_asset_spend_carrier_proves_no_membership_so_the_door_must_require_the_membership_carrier`).
#[test]
fn a_transfer_missing_either_carrier_is_refused_before_anything_is_read() {
    let good = a_transfer();
    assert!(AssetSpendTx::decode(&good.encode()).is_some(), "CALIBRATION: the honest one decodes");
    let no_membership = AssetSpendTx { membership_carrier: Vec::new(), ..good.clone() };
    assert!(
        AssetSpendTx::decode(&no_membership.encode()).is_none(),
        "⛔ A TRANSFER WITH NO MEMBERSHIP CARRIER WAS ACCEPTED — its copath is free, so it spends a \
         note nobody ever paid it"
    );
    let no_validity = AssetSpendTx { validity_carrier: Vec::new(), ..good.clone() };
    assert!(
        AssetSpendTx::decode(&no_validity.encode()).is_none(),
        "⛔ A TRANSFER WITH NO VALIDITY CARRIER WAS ACCEPTED — nothing bounds what it pays out"
    );
    // An over-cap carrier is refused BEFORE it is ever verified, so a huge blob is never opened.
    let huge = AssetSpendTx {
        validity_carrier: vec![0u8; ASSET_SPEND_CARRIER_BYTES_MAX + 1],
        ..good.clone()
    };
    assert!(AssetSpendTx::decode(&huge.encode()).is_none(), "an over-cap carrier is refused");
    // The sentinel nullifier is the IMT's empty-tree low leaf and is never a real spend.
    let sentinel = AssetSpendTx { nullifier: [0u8; 32], ..good.clone() };
    assert!(AssetSpendTx::decode(&sentinel.encode()).is_none(), "the sentinel is not a spend");
    // An owner list that does not line up files a note under the wrong owner.
    let skewed = AssetSpendTx { owner_clues: vec![vec![0x5a; 8]], ..good.clone() };
    assert!(AssetSpendTx::decode(&skewed.encode()).is_none(), "one owner per output, exactly");
    assert_eq!(good.owner_clues.len(), ASSET_SPEND_OUTPUTS);
    // ⛔ DB-273 §19.6 L3 (c) — an output filed for NOBODY, or under an over-wide clue, is not a transfer.
    let ownerless = AssetSpendTx { owner_clues: vec![vec![0x5a; 8], Vec::new()], ..good.clone() };
    assert!(AssetSpendTx::decode(&ownerless.encode()).is_none(), "⛔ an output with no owner clue decoded");
    let wide = AssetSpendTx {
        owner_clues: vec![vec![0x5a; 8], vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX + 1]],
        ..good.clone()
    };
    assert!(AssetSpendTx::decode(&wide.encode()).is_none(), "⛔ an over-wide owner clue decoded");
}

/// ⛔ §AG CLASS 9 — A BYTE BUFFER SIZED BY A LANE COUNT. The commitment reader once walked
/// `DIGEST_LANES` little-endian u64s (64 bytes at the current width); a `< 32` guard let a
/// 32..63-byte note reach `copy_from_slice` and PANIC a consensus door. A remote crash, not a refusal.
/// The reader is now the injective decode of the 32-byte front, so the two refusals it must make are:
/// a note too short to hold a commitment, and a note whose front is not a canonical digest at all.
#[test]
fn a_note_shorter_than_the_commitment_it_claims_is_refused_and_never_panics() {
    let mut t = a_transfer();
    t.notes[0] = vec![7u8; crate::spend_frontier::NOTE_CM_BYTES - 1];
    assert!(
        AssetSpendTx::decode(&t.encode()).is_none(),
        "a note too short to hold its own commitment is REFUSED at decode"
    );
    // And the reader itself refuses rather than reading past the end, for any caller that reaches it.
    assert!(
        t.output_commitments().is_none(),
        "⛔ the commitment reader walked past the end of a short note — that is a panic on a door"
    );
    // A front that is NOT a canonical digest (bit 255 set) is malformed, not an alternative spelling.
    let mut u = a_transfer();
    u.notes[1][31] |= 0x80;
    assert!(
        u.output_commitments().is_none(),
        "a non-canonical commitment front must be refused, never laundered into some digest"
    );
    // And the honest transfer's notes still read back as exactly the commitments the prover welded.
    let good = a_transfer();
    let cms = good.output_commitments().expect("canonical fronts decode");
    for (n, cm) in good.notes.iter().zip(cms.iter()) {
        assert_eq!(
            &n[..crate::spend_frontier::NOTE_CM_BYTES],
            &crate::spend_frontier::leaf_to_cm_bytes(*cm)[..],
            "the reader is the exact inverse of the one production writer"
        );
    }
}
/// ⭐⭐⭐ §BR-14 item 4 — A TOKEN CREATION BURNS ITS PRICE INTO THE FOUR POOLS, ON EVERY NODE, AND ONE NOTE PAYS ONCE.
/// - A (producer) and B (fed only the blocks) both fold the creation: both registries hold it, both credit EXACTLY the
///   symbol's price + the network fee to the pools (split 40/25/25/10 at the era's shares), and both hold the change.
/// - TAMPER (double pay): a second creation built over the SAME fee note (same nullifier, a valid burn for itself) is
///   refused at both nodes' doors by the spent set.
/// CALIBRATION: the pools agree and hold nothing from this creation before its block folds.
/// TWO-PARTY-REVIEWED: every claim is asserted on the producer AND the peer.
#[test]
fn br14_a_token_creation_burns_its_price_into_the_four_pools_on_every_node() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let mut c = a_token();
    let ts = crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut c, 14, 5_000);
    let (pa0, pb0) = (a.peg().fee_pools(), b.peg().fee_pools());
    assert_eq!(pa0, pb0, "CALIBRATION: the pools agree before the creation");
    let registry0 = a.token_registry_root();
    assert!(matches!(a.publish_asset_create(&c), crate::node::AssetSpendOutcome::Published), "the paid creation publishes");
    let blk = a.produce(ts + 500, crate::hash::Hash32::hash(b"br14-create-fr"), crate::hash::Hash32::hash(b"br14-create-mc")).expect("A lays it");
    assert!(matches!(b.ingest_block(blk, ts + 500), crate::relay::RelayOutcome::Added(_)), "B grafts the creation block");
    let ts = crate::node::tests::produce_past_the_fold(&mut a, &mut [&mut b], ts + 500, 500);
    let (pa, pb) = (a.peg().fee_pools(), b.peg().fee_pools());
    eprintln!("[br14-create] pools before {pa0:?} · A after {pa:?} · B after {pb:?}");
    assert_eq!(pa, pb, "⛔ §BR-14: the producer and the peer credited different pools for one creation");
    let paid = u128::from(c.creation_price() + usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC);
    assert_eq!(
        pa.total() - pa0.total(),
        paid,
        "⛔ §BR-14 item 4: the pools must take exactly the symbol's price + the network fee (the creation's burn)"
    );
    assert_ne!(a.token_registry_root(), registry0, "the creation registered on A");
    assert_eq!(a.token_registry_root(), b.token_registry_root(), "⛔ one registry on both nodes");
    let change_cm = <[u8; 32]>::try_from(&c.fee.change_note[..32]).expect("cm");
    assert!(a.holds_record_with_cm(&change_cm) && b.holds_record_with_cm(&change_cm), "⛔ the burn's change is held on both nodes");
    // TAMPER — the same note pays a second creation.
    let mut again = a_token();
    again.name = "Gate Token, paid twice".into();
    again.bytecode = crate::dsol::compile(crate::dsol::DsolKind::Token, "GATE", &again.name).bytecode;
    again.asset_id = again.derived_id();
    again.fee = crate::node::objects::asset_tx::creation_fee_leg_for_test(&a, &again, 14);
    assert_eq!(again.fee.nullifier, c.fee.nullifier, "CALIBRATION: the second creation spends the SAME fee note");
    assert!(again.fee_carrier_verifies(), "CALIBRATION: its burn is valid for itself — only the spent set can refuse it");
    for (who, n) in [("A", &mut a), ("B", &mut b)] {
        let out = n.publish_asset_create(&again);
        assert!(
            matches!(out, crate::node::AssetSpendOutcome::Refused(_) | crate::node::AssetSpendOutcome::NotPublished),
            "⛔ {who} admitted a creation paid with an already-spent note: {out:?}"
        );
    }
    let _ = ts;
}

/// ⛔⛔⛔ §BR-14 TAMPER — A CREATION WHOSE BURN IS ONE UNIT SHORT, OR WAS PROVEN FOR ANOTHER CREATION, PAYS NOTHING: both
/// doors (the blob-only `admissible` and the state door `Node::creation_fee_refusal` at the Fold door, the one the fold
/// applies) refuse it on BOTH nodes. CALIBRATION: the honest creation passes the same doors on both nodes.
/// TWO-PARTY-REVIEWED: every verdict is asserted on both nodes.
#[test]
fn br14_a_creation_whose_burn_is_short_or_lifted_is_refused_on_every_node() {
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let mut c = a_token();
    crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut c, 15, 5_000);
    let admit = |x: &AssetCreateTx| {
        crate::chain_object::admissible(&x.wire(), 10, crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false)
    };
    let fold_door = |n: &crate::node::Node, x: &AssetCreateTx| n.creation_fee_refusal(x, crate::respend::MemberDoor::Fold);
    assert!(admit(&c), "CALIBRATION: the honest paid creation is admissible");
    assert_eq!((fold_door(&a, &c), fold_door(&b, &c)), (None, None), "CALIBRATION: the honest burn passes the fold door on both nodes");
    // SHORT: the burn destroys price − 1 (a valid proof of a smaller burn into this creation's own burn opening).
    let mut short = c.clone();
    {
        let mut w = super::creation_fee_witness_for_test(&c, 15);
        w.out0_value -= 1;
        w.out1_value += 1;
        let (carrier, cms, _nf, _lc) =
            usdm_decider::whir_rec_block::prove_bond_validity_carrier_with_commit_bytes(&w, w.out0_value).expect("the short burn proves");
        short.fee.carrier = carrier;
        short.fee.change_note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cms[1]));
    }
    // LIFTED: the honest burn, re-attached to ANOTHER creation at the same price.
    let mut lifted = a_token();
    lifted.name = "Gate Token, a lifted burn".into();
    lifted.bytecode = crate::dsol::compile(crate::dsol::DsolKind::Token, "GATE", &lifted.name).bytecode;
    lifted.asset_id = lifted.derived_id();
    assert_eq!(lifted.creation_price(), c.creation_price(), "CALIBRATION: the lifted creation costs the same");
    lifted.fee = c.fee.clone();
    for (what, x) in [("one unit short", &short), ("lifted from another creation", &lifted)] {
        assert!(!x.fee_carrier_verifies(), "⛔ §BR-14: a burn {what} verified");
        assert!(!admit(x), "⛔ §BR-14: the pool door admitted a creation whose burn is {what}");
        assert!(
            fold_door(&a, x).is_some() && fold_door(&b, x).is_some(),
            "⛔ §BR-14: a node's fold door accepted a creation whose burn is {what}"
        );
        assert!(
            matches!(a.publish_asset_create(x), crate::node::AssetSpendOutcome::Refused(_)),
            "⛔ §BR-14: the publisher took a creation whose burn is {what}"
        );
    }
}

/// A token creation by the key `pk`: its facts, its id, no fee yet and no supply.
fn af34_token(symbol: &str, pk: &[u8]) -> AssetCreateTx {
    let name = format!("{symbol} of the supply pin");
    let mut c = AssetCreateTx {
        kind: AssetKind::Token,
        symbol: symbol.to_string(),
        name: name.clone(),
        logo: [0u8; 32],
        bytecode: crate::dsol::compile(crate::dsol::DsolKind::Token, symbol, &name).bytecode,
        creator: crate::pqauth::pubkey_id(pk),
        asset_id: [0u8; 32],
        fee: super::CreationFee::default(),
        art: Vec::new(),
        supply: None,
    };
    c.asset_id = c.derived_id();
    c
}

/// The words of `c`'s whole supply, as its creator's wallet builds them: a real mint carrier opening a note to `amount`
/// under the asset's own tag, and the creator's real signature over the mint message. `(the supply, the note's front)`.
fn af34_supply(c: &AssetCreateTx, pk: &[u8], sk: &[u8], amount: u64, seed: u64) -> (super::CreationSupply, [u8; 32]) {
    let opening = usdm_decider::poseidon2_compress::lanes_of(&[0xAF34, seed, 7, 7]);
    let (mint_carrier, cm) = usdm_decider::whir_rec_block::prove_asset_mint_validity_bytes(amount, c.asset_tag(), &opening).expect("a real mint carrier");
    let front = crate::spend_frontier::leaf_to_cm_bytes(cm);
    // O1-INFINITY-REVIEWED: one fixed-width (`PQ_NOTE_BYTES`) in-memory note handed to a test's own object; nothing is persisted.
    let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    note[..crate::spend_frontier::NOTE_CM_BYTES].copy_from_slice(&front);
    let owner_clue = vec![0x5a; crate::peg_in_tx::OWNER_CLUE_MAX];
    let creator_sig = crate::pqauth::ml_dsa_sign(&super::creation_supply_msg(&c.asset_id, amount, &front, &crate::oli::owner_clue_digest(&owner_clue), "", c.art.len()), sk).expect("the creator signs its supply");
    (super::CreationSupply { amount, note, mint_carrier, owner_clue, creator_pubkey: pk.to_vec(), creator_sig, collection: String::new() }, front)
}

/// The separate mint the shipped wallet used to send for `c`: the same note and carrier, the creator's signature over
/// the MINT's message, and NO registry witness.
fn af34_mint_with_no_witness(c: &AssetCreateTx, s: &super::CreationSupply, sk: &[u8]) -> AssetMintTx {
    let mut with = c.clone();
    with.supply = Some(s.clone());
    let mut m = with.as_mint().expect("a creation with a supply names its mint");
    m.creator_sig = crate::pqauth::ml_dsa_sign(&super::asset_mint_msg(&c.asset_id, m.amount, &m.note[..32], &crate::oli::owner_clue_digest(&m.owner_clue), ""), sk).expect("the creator signs its mint");
    m
}

/// A lays one block, B takes it, both fold past it. Returns the time to go on from.
fn af34_land(a: &mut crate::node::Node, b: &mut crate::node::Node, ts: u64, tag: &[u8]) -> u64 {
    let blk = a.produce(ts, crate::hash::Hash32::hash(tag), crate::hash::Hash32::hash(b"af34-mc")).expect("A produces");
    assert!(matches!(b.ingest_block(blk, ts), crate::relay::RelayOutcome::Added(_)), "PRECONDITION: B grafts A's block");
    crate::node::tests::produce_past_the_fold(a, &mut [b], ts, 100) + 500
}

/// ⭐⭐⭐ FINDING A-F34 — AN ASSET CREATED WITH ITS SUPPLY IS MINTED ON THE PEER, WHATEVER THE TOKEN REGISTRY HOLDS.
///
/// MEASURED on three real nodes first (2026-11-11, check `nft`, build c492d893): the creator's wallet held 0 units of
/// an NFT every node had registered. The shipped wallet sent a creation and then a separate mint with no registry
/// witness; an empty witness opens the registry only while the asset's leaf is itself a peak.
///
/// RED FIRST, the old shape, on two nodes through blocks: two assets are created (no supply) and each is then minted the
/// way the wallet did it. The FIRST asset's mint lands (one asset in the registry: its leaf is a peak). The SECOND
/// asset's mint is taken by A's door and a block carries it, and NEITHER node holds its supply note: the creator of
/// every second asset paid and held nothing.
/// THE RULE: two more assets are created WITH their supply, back to back (the registry then holds three and four). Both
/// supply notes are in a folded record on BOTH nodes, the two spent sets agree, and each asset's issue right is spent:
/// a separate mint of either is refused at the door.
/// TAMPERS, each refused at A's door and inadmissible on its bytes: a supply signed by a key that did not create the
/// asset; the creator's supply with a larger amount than its carrier opens; the creator's supply under another asset's
/// creation; and the creator's signed supply of a pictured asset inside a copy that leaves the picture out.
/// THE FRONT-RUN: a stranger pays to create a fifth asset from the creator's own facts, with no supply, and it lands.
/// The creator's own creation WITH its supply then lands all the same and its note is held on both nodes (a creation
/// with supply does not name the creation id that the stranger's creation retired).
#[test]
fn af34_assets_created_with_their_supply_are_minted_on_the_peer_whatever_the_registry_holds() {
    use crate::node::AssetSpendOutcome as Out;
    let mk = crate::node::tests::testnet_party_folding_at_tip;
    let (mut a, mut b) = (mk(), mk());
    let (pk, sk) = crate::pqauth::ml_dsa_keypair();
    let v = crate::pqauth::MlDsaVerifier;
    let mut ts = 1_000u64;

    // ── RED FIRST: the old shape. Two creations with no supply, each minted with no registry witness.
    let mut old = Vec::new();
    for (i, sym) in ["OLDA", "OLDB"].into_iter().enumerate() {
        let mut c = af34_token(sym, &pk);
        ts = crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut c, 0x3400 + i as u64, ts) + 500;
        assert!(matches!(a.publish_asset_create(&c), Out::Published), "PRECONDITION: the old-shape creation of {sym} is admitted");
        ts = af34_land(&mut a, &mut b, ts, sym.as_bytes());
        let (supply, front) = af34_supply(&c, &pk, &sk, 4_200, i as u64);
        let mint = af34_mint_with_no_witness(&c, &supply, &sk);
        assert!(mint.creator_authorised(&v) && mint.credit_is_authorised(), "CALIBRATION: the old-shape mint of {sym} is its creator's and opens its note");
        assert!(matches!(a.publish_asset_mint(&mint), Out::Published), "the door takes the old-shape mint of {sym} (it asks nothing of the registry)");
        ts = af34_land(&mut a, &mut b, ts, &[sym.as_bytes(), b"-mint"].concat());
        old.push((sym, front));
    }
    assert_eq!(a.dsol_registry_size().0, 2, "CALIBRATION: two assets are registered");
    assert_eq!(a.token_registry_root(), b.token_registry_root(), "CALIBRATION: one registry on both nodes");
    assert!(a.holds_record_with_cm(&old[0].1) && b.holds_record_with_cm(&old[0].1), "CALIBRATION: the FIRST asset's witness-less mint lands (its leaf is a peak)");
    assert!(
        !a.holds_record_with_cm(&old[1].1) && !b.holds_record_with_cm(&old[1].1),
        "RED EXPECTED FOR THE OLD SHAPE: the SECOND asset's witness-less mint was refused at the fold on both nodes. If this note is held, the registry answered an empty witness for a leaf that is not a peak"
    );

    // ── THE RULE: two assets created WITH their supply, back to back (the registry holds three, then four)
    let mut made = Vec::new();
    for (i, sym) in ["NEWA", "NEWB"].into_iter().enumerate() {
        let mut c = af34_token(sym, &pk);
        let (supply, front) = af34_supply(&c, &pk, &sk, 7_700 + i as u64, 10 + i as u64);
        c.supply = Some(supply);
        ts = crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut c, 0x3410 + i as u64, ts) + 500;
        assert_eq!(AssetCreateTx::decode(&c.encode()).as_ref(), Some(&c), "the creation with its supply round-trips");
        assert!(c.supply_authorised(&v) && crate::chain_object::admissible(&c.wire(), 10, 0, false), "the creation with its supply is admissible on its bytes");
        made.push((c, front));
    }
    // both are pooled before either lands: nothing has to happen between an asset and its supply
    for (c, _) in &made {
        assert!(matches!(a.publish_asset_create(c), Out::Published), "⛔ A's door refuses a creation that carries its creator's supply");
    }
    let (nf_a, nf_b) = (a.nullifier_root(), b.nullifier_root());
    ts = af34_land(&mut a, &mut b, ts, b"af34-new");
    assert_eq!(a.dsol_registry_size().0, 4, "both assets are registered");
    assert_eq!(a.token_registry_root(), b.token_registry_root(), "⛔ two registries after the creations with supply");
    for (c, front) in &made {
        for (who, n) in [("A", &a), ("B", &b)] {
            assert!(n.holds_record_with_cm(front), "⛔ {who} does not hold the supply of {}: an asset was created and its creator holds nothing", c.symbol);
        }
        // the issue right is spent: no mint of this asset can follow
        let again = af34_mint_with_no_witness(c, c.supply.as_ref().expect("its supply"), &sk);
        assert!(again.creator_authorised(&v), "CALIBRATION: the later mint is its creator's own");
        assert!(!matches!(a.publish_asset_mint(&again), Out::Published), "⛔ a separate mint of {} was taken after its creation minted it", c.symbol);
        assert!(!matches!(a.publish_asset_create(c), Out::Published), "⛔ the same creation was taken twice");
    }
    assert!(a.nullifier_root() != nf_a && b.nullifier_root() != nf_b, "the creations retired their issue rights and their fee notes");
    assert_eq!(a.nullifier_root(), b.nullifier_root(), "⛔ the two nodes disagree about what is spent");

    // ── TAMPERS, each refused at the door and on its bytes
    let (pk2, sk2) = crate::pqauth::ml_dsa_keypair();
    let mut victim = af34_token("TAMP", &pk);
    let (true_supply, true_front) = af34_supply(&victim, &pk, &sk, 5_000, 20);
    ts = crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut victim, 0x3420, ts) + 500;
    // (1) a stranger's key states the supply of the creator's asset
    let mut stolen = victim.clone();
    stolen.supply = Some(af34_supply(&victim, &pk2, &sk2, 5_000, 21).0);
    // (2) the creator's supply, a larger amount than its carrier opens
    let mut inflated = victim.clone();
    inflated.supply = Some(super::CreationSupply { amount: 5_000_000, ..true_supply.clone() });
    // (3) the creator's supply of ANOTHER asset under this creation
    let mut lifted = victim.clone();
    lifted.supply = made[0].0.supply.clone();
    // (4) the creator's signed supply of a PICTURED asset, lifted into a creation that leaves the picture out
    let art = a_png(2_000, 0x34);
    let mut pictured = pictured_nft(crate::pqauth::pubkey_id(&pk), &art, true);
    let (pictured_supply, _) = af34_supply(&pictured, &pk, &sk, 1, 22);
    pictured.supply = Some(pictured_supply);
    assert!(pictured.supply_authorised(&v), "CALIBRATION: the pictured creation's own supply verifies");
    let mut stripped = pictured.clone();
    stripped.art.clear();
    assert!(stripped.art.is_empty() && stripped.logo == pictured.logo && stripped.asset_id == pictured.asset_id, "CALIBRATION: the copy is the same asset with its picture left off the chain (a creation may do that)");
    assert!(!stripped.supply_authorised(&v), "⛔ the creator's signed supply verifies inside a creation that leaves the picture out");
    for (what, t) in [("a stranger's key", &stolen), ("an amount its carrier does not open", &inflated), ("another asset's supply", &lifted)] {
        assert!(!t.supply_authorised(&v), "⛔ a creation whose supply is {what} passes as authorised");
        assert!(!crate::chain_object::admissible(&t.wire(), 10, 0, false), "⛔ a creation whose supply is {what} is admissible on its bytes");
        assert!(!matches!(a.publish_asset_create(t), Out::Published), "⛔ A's door took a creation whose supply is {what}");
        let r = crate::node::objects::asset_tx::apply_chain_asset_object(&mut b, &t.wire());
        assert!(matches!(r, super::AssetApply::CreateRefused(_)), "⛔ the fold applied a creation whose supply is {what}: {r:?}");
    }
    assert_eq!(b.dsol_registry_size().0, 4, "⛔ a refused creation registered an asset");

    // ── THE FRONT-RUN: a stranger creates the same asset first, with no supply; the creator's own creation still lands
    let mut front_run = af34_token("TAMP", &pk);
    assert_eq!(front_run.asset_id, victim.asset_id, "PRECONDITION: the same asset (a creation is not signed by the creator it names)");
    ts = crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut front_run, 0x3430, ts) + 500;
    assert!(matches!(a.publish_asset_create(&front_run), Out::Published), "PRECONDITION: the stranger's supply-less creation is admitted");
    ts = af34_land(&mut a, &mut b, ts, b"af34-front-run");
    assert_eq!(a.dsol_registry_size().0, 5, "PRECONDITION: the stranger's creation registered the asset");
    victim.supply = Some(true_supply);
    assert!(matches!(a.publish_asset_create(&victim), Out::Published), "⛔ FRONT-RUN: the creator's own creation with its supply is refused because a stranger created the asset first");
    ts = af34_land(&mut a, &mut b, ts, b"af34-victim");
    for (who, n) in [("A", &a), ("B", &b)] {
        assert!(n.holds_record_with_cm(&true_front), "⛔ FRONT-RUN: {who} does not hold the creator's supply after a stranger created the asset first");
        // the creator's creation is a second, PAID leaf of the same asset (the registry is peaks only: no state grows
        // with it), and the asset's issue right is spent, so the supply is fixed whoever created the asset first
        assert_eq!(n.dsol_registry_size().0, 6, "{who}: the creator's own creation was applied");
        assert_eq!(n.sparse_spent_verdict(&super::issue_right_nf(&victim.asset_id)), crate::nf_sparse::SpentVerdict::Spent, "⛔ FRONT-RUN: on {who} the asset's issue right is still open after its creator issued the supply");
    }
    // and the stranger cannot answer in kind: a second creation with a supply of this asset is refused at the door (the
    // right is spent) whatever key signs it, and a supply-less copy of the creation is refused by its creation id
    let mut again = af34_token("TAMP", &pk);
    again.supply = Some(af34_supply(&again, &pk, &sk, 5_000, 23).0);
    let _ = crate::node::objects::asset_tx::pay_creation_fee_for_test(&mut a, &mut [&mut b], &mut again, 0x3440, ts);
    let r = a.publish_asset_create(&again);
    assert!(matches!(r, Out::Refused(why) if why.contains("already been issued")), "⛔ a second supply of one asset was not refused by its spent issue right: its supply is not fixed");
    again.supply = None;
    let r = a.publish_asset_create(&again);
    assert!(matches!(r, Out::Refused(why) if why.contains("already created")), "⛔ a third creation of one asset was not refused by its spent creation id");
    assert_eq!(a.token_registry_root(), b.token_registry_root(), "⛔ two registries at the end");
    assert_eq!(a.nullifier_root(), b.nullifier_root(), "⛔ two spent sets at the end");
}
