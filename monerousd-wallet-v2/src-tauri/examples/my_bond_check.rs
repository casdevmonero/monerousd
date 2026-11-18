// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// LIVE proof of `wallet_my_bond` — the Earn screen mirroring the wallet's OWN bonded weight. stdin line1 = the
// wallet mnemonic. It derives the wallet's validator id (w.b = blake3(spend_pk) — the SAME id the bond/unbond
// carriers weld) and queries the node's `/get_validator_bond` for that one public row. The bond is a public
// protocol quantity, so this leaks nothing (the wallet asks only for its own id). Run AFTER `bond_check` has
// bonded this wallet: proves the wallet reads back its own non-zero bond, chain-derived + restart-proof.
use monerousd_wallet_v2_lib::pq;
use std::io::Read;

const NODE: &str = "http://127.0.0.1:27780";

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let seed = s.lines().next().expect("line1 mnemonic").trim();
    let keys = pq::restore(seed).expect("restore wallet");
    let voter_id = hex::encode(keys.b); // = blake3(spend_pk) = the validator id the bond carrier welds
    let ag = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(10)).build();

    let resp: serde_json::Value = ag
        .post(&format!("{NODE}/get_validator_bond"))
        .send_json(serde_json::json!({ "voter_id": voter_id }))
        .expect("get bond")
        .into_json()
        .expect("bond json");
    let bond = resp.get("bond").and_then(|b| b.as_u64()).unwrap_or(0);

    println!("voter_id={voter_id} bond={bond} usdm={:.8} is_validator={}", bond as f64 / 1e8, bond > 0);
    assert!(bond > 0, "the wallet must read back its OWN non-zero bond after bonding (live per-validator lookup)");
    println!("OK — wallet_my_bond reads this wallet's OWN bonded weight live from the chain (public per-validator row).");
}
