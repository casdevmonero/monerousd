// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Letter self-custodial crypto — authenticated sealed-sender roundtrip + adversarial rejects. Run as an
//! integration test (compiles the lib, not its in-crate #[cfg(test)] modules), so a genuine two-party letter
//! is proven: TWO independent wallet identities, sender authenticated, impersonation/tamper/wrong-recipient
//! all refused.

use monerousd_wallet_v2_lib::{letter, pq};

#[test]
fn a_letter_is_sealed_to_one_wallet_authenticated_from_another_and_forgery_is_refused() {
    // Two INDEPENDENT wallet identities (seed-derived) — a real sender and a real recipient, plus an attacker.
    let alice = pq::derive_keys(&[7u8; 32]);
    let bob = pq::derive_keys(&[9u8; 32]);
    let eve = pq::derive_keys(&[13u8; 32]);

    let blob = letter::seal(&bob.handle_address, &alice, &alice.handle_address, b"meet at the old oak")
        .expect("alice seals a letter to bob");

    // Bob (the recipient) opens + AUTHENTICATES it — real PQ end to end; he learns the true sender.
    let opened = letter::open_authenticated(&blob, &bob.scan_ek, &bob.scan_dk).expect("bob opens his letter");
    assert_eq!(opened.msg, b"meet at the old oak");
    assert_eq!(opened.from_addr, alice.handle_address, "recipient learns the AUTHENTICATED sender, no one else");

    // A DIFFERENT recipient (Eve) cannot open it — wrong ML-KEM key → MAC fails (implicit rejection).
    assert!(
        letter::open_authenticated(&blob, &eve.scan_ek, &eve.scan_dk).is_none(),
        "a letter not sealed to Eve must never open for her"
    );

    // A TAMPERED byte fails the MAC.
    let mut bad = blob.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(
        letter::open_authenticated(&bad, &bob.scan_ek, &bob.scan_dk).is_none(),
        "a tampered letter must be refused, not silently altered"
    );

    // IMPERSONATION: Eve seals a real letter to Bob but stamps ALICE's from_addr. The signature is Eve's key,
    // whose blake3 != Alice's spend tag, so authentication rejects — no one can send AS someone else.
    let forged = letter::seal(&bob.handle_address, &eve, &alice.handle_address, b"send me 100")
        .expect("eve can seal (to bob) ...");
    assert!(
        letter::open_authenticated(&forged, &bob.scan_ek, &bob.scan_dk).is_none(),
        "... but a letter claiming a from_addr it cannot sign for MUST be refused (no impersonation)"
    );
}
