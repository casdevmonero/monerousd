// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::wrapped_mint_asset_gate_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
//! The wrapped-mint credit used to let a caller choose BOTH the amount it received AND — because the
//! node tagged nothing — the asset. These pin that a proof now decides both.

use usdm_decider::whir_rec_block::{
    asset_note_cm, prove_asset_mint_validity_bytes, verify_asset_mint_validity_bytes,
    wrapped_asset_tag_u32, USDM_ASSET_TAG,
};

const WBTC_ID: u32 = 1;
const SK: crate::spend_frontier::Digest4 =
        usdm_decider::poseidon2_compress::lanes_of_const(&[11, 22, 33, 44]);
const AUTHORIZED: u64 = 100;

/// ⛔⛔⛔ THE OVER-MINT: a note sealed for 1,000,000 against an authorized 100. Before this gate the
/// caller simply received the larger note while the asset's committed pair advanced by 100.
#[test]
fn a_wrapped_note_sealed_for_more_than_the_authorized_mint_is_refused() {
    let tag = wrapped_asset_tag_u32(WBTC_ID);
    let (honest, honest_cm) = prove_asset_mint_validity_bytes(AUTHORIZED, tag, &SK).unwrap();
    assert!(
        verify_asset_mint_validity_bytes(&honest, honest_cm, AUTHORIZED, tag),
        "an honest wrapped credit still lands"
    );
    let (greedy, greedy_cm) = prove_asset_mint_validity_bytes(1_000_000, tag, &SK).unwrap();
    assert!(
        !verify_asset_mint_validity_bytes(&greedy, greedy_cm, AUTHORIZED, tag),
        "a note sealed for 1e6 must NOT be credited under an authorized 100"
    );
    assert!(
        !verify_asset_mint_validity_bytes(&honest, greedy_cm, AUTHORIZED, tag),
        "nor by pairing the honest carrier with the bigger note"
    );
    assert!(
        !verify_asset_mint_validity_bytes(&[], honest_cm, AUTHORIZED, tag),
        "and an absent carrier is a refusal, never a pass"
    );
}

/// ⛔⛔⛔ THE WRONG ASSET. Before the tag existed EVERY wrapped mint produced an all-zero-tag note —
/// which IS a USDm note — so minting 1 wBTC credited a note the wallet spends as 1 unit of USDm.
#[test]
fn a_wrapped_mint_cannot_credit_a_usdm_note() {
    let tag = wrapped_asset_tag_u32(WBTC_ID);
    let (carrier, cm) = prove_asset_mint_validity_bytes(AUTHORIZED, tag, &SK).unwrap();
    assert!(verify_asset_mint_validity_bytes(&carrier, cm, AUTHORIZED, tag));
    assert!(
        !verify_asset_mint_validity_bytes(&carrier, cm, AUTHORIZED, USDM_ASSET_TAG),
        "a wBTC credit must NOT verify as USDm"
    );
    let untagged_cm = asset_note_cm(AUTHORIZED, USDM_ASSET_TAG, SK);
    assert_ne!(untagged_cm, cm, "a USDm note and a wBTC note of the same amount differ");
    assert!(
        !verify_asset_mint_validity_bytes(&carrier, untagged_cm, AUTHORIZED, tag),
        "the untagged note an un-gated mint would have produced cannot be credited"
    );
}

/// ⛔ ONE ASSET'S AUTHORIZATION CANNOT CREDIT ANOTHER'S NOTE.
#[test]
fn one_wrapped_assets_authorization_cannot_credit_another() {
    let (wbtc, weth) = (wrapped_asset_tag_u32(1), wrapped_asset_tag_u32(2));
    assert_ne!(wbtc, weth);
    let (carrier, cm) = prove_asset_mint_validity_bytes(AUTHORIZED, wbtc, &SK).unwrap();
    assert!(!verify_asset_mint_validity_bytes(&carrier, cm, AUTHORIZED, weth));
}

/// ⭐ NODE AND WALLET DERIVE ONE TAG. If they did not, the node would mint under one asset and the
/// wallet would search for another — a note valid on chain and invisible to its owner.
#[test]
fn the_registry_id_derives_one_tag_for_both_sides() {
    assert_eq!(wrapped_asset_tag_u32(7), wrapped_asset_tag_u32(7));
    assert_ne!(wrapped_asset_tag_u32(7), USDM_ASSET_TAG);
}
