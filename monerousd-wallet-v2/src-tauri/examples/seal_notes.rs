// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// Generic dev tool — read lines "<address> <amount_atomic>" from stdin and print the concatenated 1153-byte
// confidential note blobs (hex), one per line, in order. Nothing is baked in: every address and amount comes
// from stdin at run time. It exercises the wallet's OWN note format (`pq::seal_note` → Poseidon `note_cm`), so
// a note it seals is a spendable membership leaf the V2 wallet can later scan + spend. Used device-locally to
// assemble note sets; the amounts/addresses it seals stay device-local and are never committed.
use monerousd_wallet_v2_lib::pq;
use std::io::Read;

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).expect("read stdin");
    let mut out = String::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // The amount is the LAST whitespace token; the address (cnBase58, no spaces) is everything before it.
        let mut it = line.rsplitn(2, char::is_whitespace);
        let amount: u64 = it.next().expect("amount token").parse().expect("amount must be a u64");
        let addr = it.next().expect("address token").trim();
        let (_tag, _b, ek) = pq::parse_address(addr).expect("valid recipient address");
        let note = pq::seal_note(&ek, amount).expect("seal a note to the recipient");
        out.push_str(&hex::encode(note));
    }
    print!("{out}");
}
