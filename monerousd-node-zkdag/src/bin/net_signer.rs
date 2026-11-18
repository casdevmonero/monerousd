// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.


//! The real-node checks' signer: prints the JSON body a validator operator or a watchtower would post, signed with a node's own
//! seat key read from its data folder. It holds no chain logic: every message comes from the function the node's door verifies
//! against, and every verdict comes from real node processes (`scratchpad/net/`).

use usdmd_node::hash::Hash32;

const ML_DSA_65_SK: usize = 4032;

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn key(path: &str) -> (Vec<u8>, Vec<u8>) {
    let b = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
    (b[4..4 + n].to_vec(), b[4 + n..4 + n + ML_DSA_65_SK].to_vec()) // a seed-provisioned key file carries a trailer after the secret
}

fn attest(msg: &[u8], keys: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for k in keys {
        let (pk, sk) = key(k);
        let sig = usdmd_node::pqauth::ml_dsa_sign(msg, &sk).expect("the seat key signs");
        out.extend_from_slice(&(pk.len() as u16).to_le_bytes());
        out.extend_from_slice(&pk);
        out.extend_from_slice(&(sig.len() as u16).to_le_bytes());
        out.extend_from_slice(&sig);
    }
    out
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
}

/// A digest drawn from the run's seed text and a purpose, canonical in every lane.
fn fresh(seed: &str, what: &[u8]) -> usdmd_node::spend_frontier::Digest4 {
    let h = Hash32::hash(&[seed.as_bytes(), what].concat());
    let w: Vec<u64> = h.0.chunks_exact(4).map(|c| u64::from(u32::from_le_bytes(c.try_into().expect("4"))) % 1_000_000_007).collect();
    usdm_decider::poseidon2_compress::lanes_of(&w)
}

fn owner_of(seed: &str) -> usdm_decider::whir_rec_block::NoteOwner {
    usdm_decider::whir_rec_block::NoteOwner { ask: fresh(seed, b"ask"), nk: fresh(seed, b"nk"), seed: fresh(seed, b"note-seed") }
}

fn note_of(cm: usdmd_node::spend_frontier::Digest4) -> Vec<u8> {
    let mut n = vec![0u8; usdmd_node::cover::PQ_NOTE_BYTES];
    n[..usdmd_node::spend_frontier::NOTE_CM_BYTES].copy_from_slice(&usdmd_node::spend_frontier::leaf_to_cm_bytes(cm));
    n
}

fn clue(seed: &str, index: u64) -> Vec<u8> {
    let sk = usdmd_node::oli::derive_loc_sk(blake3::hash(seed.as_bytes()).as_bytes());
    let salt = usdmd_node::oli::address_salt(&sk, "chg", index);
    usdmd_node::oli::tag_clue_bytes_v2(&usdmd_node::oli::locator_at(&sk, "chg", index), &salt, &usdmd_node::oli::address_index_hint(&sk, &salt, index))
}

fn main() {
    // A-F47: every node-key statement names the network it is signed on (`pqauth::node_statement`), so this signer fixes its
    // network exactly as a node does at genesis — the rig's own MONEROUSD_NET, the testnet when the rig sets none (no node
    // starts on the mainnet identity before launch) — or each statement it signs would name another chain and be refused.
    let net = std::env::var("MONEROUSD_NET").unwrap_or_else(|_| "testnet".to_string());
    usdmd_node::params::set_process_network_id(&usdmd_node::params::network_genesis_prefix(&net));
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        // address-key <address> <shard bits>: what anyone holding only this address computes: its index key and shard
        Some("address-key") => {
            let parsed = usdmd_node::address::parse_address_full(&a[1]).expect("an address");
            let loc = parsed.locator.expect("a locator");
            let clue = usdmd_node::oli::tag_clue_bytes_v2(&loc, &parsed.loc_salt.expect("a salt"), &parsed.loc_hint.expect("a hint"));
            let k = usdmd_node::oli::index_key(&clue);
            let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
            println!("{hex} {}", usdmd_node::oli::shard_of(&k, a[2].parse().expect("shard bits")));
        }
        // address-match <key hex> <table hex file>: the public table's entries this key opens, each `ordinal slot`
        Some("address-match") => {
            let unhex = |h: &str| (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("hex")).collect::<Vec<u8>>();
            let k: [u8; usdmd_node::oli::K_BYTES] = unhex(&a[1]).try_into().expect("a key");
            for e in unhex(std::fs::read_to_string(&a[2]).expect("a table file").trim()).chunks(usdmd_node::oli::ENTRY_BYTES) {
                if let Some((ordinal, slot)) = usdmd_node::oli::entry_for_key(e, &k) {
                    println!("{ordinal} {slot}");
                }
            }
        }
        // equivocation <key>: one validator's two votes for two blocks at one height
        Some("equivocation") => {
            let (pk, sk) = key(&a[1]);
            let vote = |tag: &[u8]| {
                let block = Hash32::hash(tag);
                usdmd_node::validator::VoteCert {
                    pubkey: pk.clone(),
                    block,
                    height: 7,
                    sig: usdmd_node::pqauth::ml_dsa_sign(&usdmd_node::pqauth::finality_vote_msg(&block, 7), &sk).expect("signs"),
                }
            };
            let (x, y) = (vote(b"net-equivocation-x"), vote(b"net-equivocation-y"));
            println!(r#"{{"vote_a_hex":"{}","vote_b_hex":"{}"}}"#, hexs(&x.to_wire()), hexs(&y.to_wire()));
        }
        // vote <key> <tag> <height>: ONE finality vote, signed on the network this process runs on (MONEROUSD_NET), as the
        // validator's own node signs it there. A-F47's real-node check signs one vote with MONEROUSD_NET=mainnet and one on the
        // testnet: the honest double life of one seed on two chains, which must never read as an equivocation on either.
        Some("vote") => {
            let (pk, sk) = key(&a[1]);
            let block = Hash32::hash(a[2].as_bytes());
            let height: u64 = a[3].parse().expect("height");
            let sig = usdmd_node::pqauth::ml_dsa_sign(&usdmd_node::pqauth::finality_vote_msg(&block, height), &sk).expect("signs");
            println!("{}", hexs(&usdmd_node::validator::VoteCert { pubkey: pk, block, height, sig }.to_wire()));
        }
        // theft <thief key> <attesting key>...: a reserve-theft statement signed by the named seats
        Some("theft") => {
            let (thief_pk, _) = key(&a[1]);
            let thief = usdmd_node::pqauth::pubkey_id(&thief_pk);
            let statement = usdmd_node::bond_tally::reserve_move_statement(
                "BTC",
                b"tb1pREALTHIEF",
                &usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
                &[0x5au8; 32],
                3,
            );
            let msg = usdmd_node::theft_tx::theft_msg(&statement, &[thief], 100_000_000);
            println!(
                r#"{{"statement_hex":"{}","attestors_hex":"{}","offenders_hex":"{}","loss_sats":100000000}}"#,
                hexs(&statement),
                hexs(&attest(&msg, &a[2..])),
                hexs(&thief)
            );
        }
        // wrapped <asset id> <ratio bps> <key>...: a wrapped-asset registration signed by the named seats
        Some("wrapped") => {
            let (asset, ratio): (u32, u32) = (a[1].parse().expect("asset"), a[2].parse().expect("ratio"));
            let msg = usdmd_node::peg::PegLedger::wrapped_register_msg(0, asset, 0, ratio);
            println!(r#"{{"asset_id":{asset},"ratio_bps":{ratio},"epoch_id":0,"attestors_hex":"{}"}}"#, hexs(&attest(&msg, &a[3..])));
        }
        // unbond-clue <text>: a real OLI clue the operator names the returned bond's owner with
        Some("unbond-clue") => {
            let sk = usdmd_node::oli::derive_loc_sk(blake3::hash(a[1].as_bytes()).as_bytes());
            let salt = usdmd_node::oli::address_salt(&sk, "chg", 0);
            let clue = usdmd_node::oli::tag_clue_bytes_v2(
                &usdmd_node::oli::locator_at(&sk, "chg", 0),
                &salt,
                &usdmd_node::oli::address_index_hint(&sk, &salt, 0),
            );
            println!(r#"{{"own":true,"note_clue_hex":"{}"}}"#, hexs(&clue));
        }
        // wrapped-blind <seed text>: the deposit blind a wrapped mint names, as the hex the reserve route takes
        Some("wrapped-blind") => println!("{}", hexs(&usdmd_node::spend_frontier::digest_to_lane_bytes(&fresh(&a[1], b"blind")))),
        // wrapped-mint <seed text> <asset> <minted> <deposit sats> <reserve address>: the mint request a depositor posts
        Some("wrapped-mint") => {
            let (asset, minted, deposit): (u32, u64, u64) = (a[2].parse().expect("asset"), a[3].parse().expect("minted"), a[4].parse().expect("deposit"));
            let owner = owner_of(&a[1]);
            let blind = fresh(&a[1], b"blind");
            let tag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(asset);
            let (carrier, cm, _) = usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(minted, tag, &owner.opening(), &blind).expect("an authorized amount proves");
            let delta = usdmd_node::peg::PegLedger::mint_delta_commit(u128::from(minted), blind);
            println!(
                r#"{{"asset_id":{asset},"deposit_id":"{}","deposit_value":{deposit},"mint":{minted},"note_payload":"{}","reserve_address":"{}","mint_carrier_hex":"{}","delta_commit":"{}","d_blind_hex":"{}","note_clue_hex":"{}","cm_hex":"{}"}}"#,
                hexs(&usdmd_node::peg::deposit_id_for_reserve_address(&a[5])),
                hexs(&note_of(cm)),
                a[5],
                hexs(&carrier),
                hexs(&usdmd_node::spend_frontier::leaf_to_cm_bytes(delta)),
                hexs(&usdmd_node::spend_frontier::digest_to_lane_bytes(&blind)),
                hexs(&clue(&a[1], 0)),
                hexs(&usdmd_node::spend_frontier::leaf_to_cm_bytes(cm)),
            );
        }
        // wrapped-spend <seed text> <asset> <minted> <out0 value> <record> <siblings hex> <dirs 0/1> <root hex>: a transfer of the minted note
        Some("wrapped-spend") => {
            use usdmd_node::spend_frontier as sf;
            use usdm_decider::whir_rec_block as wr;
            let (asset, minted, out0, record): (u32, u64, u64, u64) = (a[2].parse().expect("asset"), a[3].parse().expect("minted"), a[4].parse().expect("out0"), a[5].parse().expect("record"));
            let lane = sf::DIGEST_LANE_BYTES;
            let sibs: Vec<sf::Digest4> = unhex(&a[6]).chunks_exact(lane).map(|b| sf::digest_from_lane_bytes(b).expect("sibling")).collect();
            let dirs: Vec<bool> = a[7].chars().map(|c| c == '1').collect();
            let root = sf::digest_from_lane_bytes(&unhex(&a[8])).expect("root");
            let owner = owner_of(&a[1]);
            let lc_blind = fresh(&a[1], b"lc-blind");
            let w = wr::AssetSpendValidityWitness {
                value_in: minted,
                owner,
                value_out: minted,
                fee: 0,
                lc_blind,
                out0_value: out0,
                out0_opening: fresh(&a[1], format!("out0-{out0}").as_bytes()),
                out1_value: minted - out0,
                out1_opening: fresh(&a[1], format!("out1-{out0}").as_bytes()),
                asset: wr::wrapped_asset_tag_u32(asset),
            };
            let leaf = wr::asset_spend_input_leaf(&w).expect("the input opens");
            let (validity, cms, nf, lc) = wr::prove_asset_spend_validity_carrier_bytes(&w).expect("an honest transfer proves");
            let mut mc = usdm_decider::note_membership_air::NoteMembershipCarrier::new(leaf, root, usdmd_node::node::Node::MEMBERSHIP_GENESIS_ACC, nf, lc_blind);
            assert!(mc.attach_membership(leaf, &sibs, &dirs), "the served copath reaches the record root");
            assert!(mc.step(root), "the one fold step proves");
            let (membership, tip_acc, tip_prev, tip_root) = mc.finalize_one_step().expect("certifies");
            let d = |x: sf::Digest4| hexs(&sf::leaf_to_cm_bytes(x));
            let notes = [note_of(cms[0]), note_of(cms[1])];
            let clues = usdmd_node::node::Node::encode_note_clue_records(&[
                (<[u8; 32]>::try_from(&notes[0][..32]).expect("32"), clue(&a[1], 1)),
                (<[u8; 32]>::try_from(&notes[1][..32]).expect("32"), clue(&a[1], 2)),
            ]);
            println!(
                r#"{{"note0":"{}","note1":"{}","nullifier":"{}","leaf_commit":"{}","validity_carrier":"{}","membership_carrier":"{}","named_record":{record},"tip_prev":"{}","tip_root":"{}","tip_acc":"{}","note_clues_hex":"{}","out_cms_hex":["{}","{}"]}}"#,
                hexs(&notes[0]), hexs(&notes[1]), d(nf), d(lc), hexs(&validity), hexs(&membership), d(tip_prev), d(tip_root), d(tip_acc), hexs(&clues), d(cms[0]), d(cms[1])
            );
        }
        _ => {
            eprintln!("usage: net_signer equivocation <key> | vote <key> <tag> <height> | theft <thief key> <key>... | wrapped <asset> <ratio> <key>... | unbond-clue <text>");
            std::process::exit(2);
        }
    }
}
