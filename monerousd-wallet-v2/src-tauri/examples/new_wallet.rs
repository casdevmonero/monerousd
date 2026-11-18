// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// Generic dev tool — draw ONE brand-new V2 wallet (fresh-random 24-word mnemonic + its PQ address) and print
// it as "<seed phrase>\t<address>". Nothing is fixed: every run mints a different wallet. This just exercises
// the wallet's own public keygen (the same the UI runs) so device-local tooling can obtain a V2-format
// address; the seed it prints must be kept device-local and NEVER committed.
use monerousd_wallet_v2_lib::pq;

fn main() {
    let (phrase, keys) = pq::generate().expect("generate a fresh wallet");
    println!("{phrase}\t{}", keys.address);
}
