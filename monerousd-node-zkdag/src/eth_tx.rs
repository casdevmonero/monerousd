// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ AN ETHEREUM TRANSACTION, ENCODED AND SIGNED BY THE NODE (docs/BRIDGE-MORE-COINS-SPEC-20261110.md §3.1): the
//! envelope that carries a vault call (`eth_vault::pay_calldata`, `rotate_calldata`, `sweep_calldata`) or the vault's
//! one-time deployment onto Ethereum.
//!
//! WHAT THIS IS. Ethereum's own wire form for a fee-market transaction (EIP-1559, type 2): the fields in RLP, the
//! digest a sender signs, the signed bytes a node hands to `eth_sendRawTransaction`, and the transaction's hash.
//! Arithmetic only: it reads no chain and holds no key.
//!
//! WHO SIGNS IT, AND WHAT THAT KEY CAN DO. The sender of a vault call is whichever custodian holds a quorum's
//! signatures first; it signs the ENVELOPE with its own Ethereum key so Ethereum will carry it and charge it gas. That
//! key moves nothing of the vault's: the vault pays out only on the custody set's signatures inside the call
//! (`eth_vault::signed_weight`), and repays the sender's gas inside the cap every signer signed. A sender that lies in
//! the envelope (another fee, another nonce) changes only what it itself pays.
//!
//! ONE ENCODING. RLP has exactly one form for a value (no leading zero in an integer, the short forms where they
//! apply); [`rlp_uint`], [`rlp_bytes`] and [`rlp_list`] emit only that form, so a transaction has one hash.
//!
//! SCALE (§9.6 question 7): one transaction is its call's bytes plus about 110 bytes of envelope; the call is bounded
//! by `eth_vault`'s own bounds (11,684 bytes at every bound). Nothing grows with the bonded set, the items in flight or
//! height, and nothing is stored.
//! AI RESISTANT (§9.6 question 8): nothing here decides value. What protects the ether is the vault's own check of the
//! custody set's signatures; this module only makes bytes Ethereum accepts, and its tests hold those bytes to a
//! transaction Ethereum's own tooling produced.
//!
//! CLASSICAL-BRIDGE-ENDPOINT: the envelope is signed with Ethereum's own signature (`eth_vault::sign`), the only one
//! Ethereum accepts for a transaction. Nothing of the MoneroUSD base layer rests on it.
//! BORROWED: EIP-1559 and EIP-2718 (the typed envelope), Ethereum's RLP.
//! Cons, quantified: none on our chain. On Ethereum: the envelope's 21,000 base gas per transaction, repaid with the
//! call's gas from the vault inside the signed cap.

use crate::eth_vault::{keccak, Address};

/// An unsigned integer as RLP: big-endian with no leading zero; zero is the empty string.
#[must_use]
pub fn rlp_uint(v: u128) -> Vec<u8> {
    let be = v.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len());
    rlp_bytes(&be[first..])
}

/// A byte string as RLP: itself when it is one byte under 0x80; else a length prefix and the bytes.
#[must_use]
pub fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return vec![b[0]];
    }
    let mut out = rlp_prefix(0x80, b.len());
    out.extend_from_slice(b);
    out
}

/// A list of already-encoded items as RLP: a length prefix and the items.
#[must_use]
pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let len: usize = items.iter().map(Vec::len).sum();
    let mut out = rlp_prefix(0xc0, len);
    for i in items {
        out.extend_from_slice(i);
    }
    out
}

/// RLP's length prefix over `base` (0x80 for a string, 0xc0 for a list): one byte up to 55, else the length's own length.
fn rlp_prefix(base: u8, len: usize) -> Vec<u8> {
    if len <= 55 {
        return vec![base + len as u8];
    }
    let be = (len as u64).to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let mut out = vec![base + 55 + (be.len() - first) as u8];
    out.extend_from_slice(&be[first..]);
    out
}

/// A 32-byte big-endian number (a signature's `r` or `s`) as an RLP integer: leading zeros dropped.
fn rlp_word(w: &[u8; 32]) -> Vec<u8> {
    let first = w.iter().position(|b| *b != 0).unwrap_or(w.len());
    rlp_bytes(&w[first..])
}

/// One fee-market transaction (EIP-1559). `to` is `None` only for the vault's one-time deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx1559 {
    pub chain_id: u64,
    pub nonce: u64,
    /// The tip per gas the sender offers, in wei.
    pub max_priority_fee_per_gas: u128,
    /// The most per gas the sender pays in all, in wei.
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Option<Address>,
    /// Wei sent with the call (zero for every vault call; a direct `deposit(tag)` carries the deposit).
    pub value: u128,
    /// O1-FOOTPRINT-REVIEWED: a vault call (`eth_vault`'s bounds: 11,684 bytes at most) or the vault's creation code.
    pub data: Vec<u8>,
}

impl Tx1559 {
    /// The nine fields a sender signs, each RLP-encoded, in order (the access list is always empty).
    fn fields(&self) -> Vec<Vec<u8>> {
        vec![
            rlp_uint(u128::from(self.chain_id)),
            rlp_uint(u128::from(self.nonce)),
            rlp_uint(self.max_priority_fee_per_gas),
            rlp_uint(self.max_fee_per_gas),
            rlp_uint(u128::from(self.gas_limit)),
            rlp_bytes(self.to.as_ref().map_or(&[][..], |a| &a[..])),
            rlp_uint(self.value),
            rlp_bytes(&self.data),
            rlp_list(&[]),
        ]
    }

    /// The digest the sender signs: `keccak256(0x02 ‖ rlp(fields))`. It binds the chain id, so a signed transaction
    /// is useless on another chain.
    #[must_use]
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut pre = vec![0x02];
        pre.extend_from_slice(&rlp_list(&self.fields()));
        keccak(&pre)
    }

    /// ⭐ THE SIGNED TRANSACTION, as `eth_sendRawTransaction` takes it: `0x02 ‖ rlp(fields ‖ y_parity ‖ r ‖ s)`.
    /// `None` for a secret that is not a valid key.
    #[must_use]
    pub fn sign(&self, secret: &[u8; 32]) -> Option<Vec<u8>> {
        let (v, r, s) = crate::eth_vault::sign(secret, &self.signing_digest())?; // CLASSICAL-CRYPTO-EXEMPT: Ethereum's own transaction signature, the only one Ethereum carries (bridge endpoint)
        let mut items = self.fields();
        items.push(rlp_uint(u128::from(v - 27)));
        items.push(rlp_word(&r));
        items.push(rlp_word(&s));
        let mut raw = vec![0x02];
        raw.extend_from_slice(&rlp_list(&items));
        Some(raw)
    }

    /// The most wei this transaction can cost its sender: `gas_limit × max_fee_per_gas + value`. `None` on overflow.
    #[must_use]
    pub fn max_cost_wei(&self) -> Option<u128> {
        u128::from(self.gas_limit).checked_mul(self.max_fee_per_gas)?.checked_add(self.value)
    }
}

/// A signed transaction's hash (what a receipt is asked by): `keccak256` of its raw bytes.
#[must_use]
pub fn tx_hash(raw: &[u8]) -> [u8; 32] {
    keccak(raw)
}

/// The address a plain deployment creates: `keccak256(rlp([sender, nonce]))[12..]` (the vault's one-time deployment;
/// its address is then a fact the chain records, never re-derived from a sender).
#[must_use]
pub fn created_address(sender: &Address, nonce: u64) -> Address {
    let h = keccak(&rlp_list(&[rlp_bytes(sender), rlp_uint(u128::from(nonce))]));
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}

#[cfg(test)]
mod eth_tx_tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        let s = s.trim().trim_start_matches("0x");
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    /// RLP's own examples (the Ethereum wiki's table): one form per value, the short forms where they apply.
    #[test]
    fn rlp_has_one_form_per_value() {
        assert_eq!(hex(&rlp_bytes(b"dog")), "83646f67");
        assert_eq!(hex(&rlp_list(&[rlp_bytes(b"cat"), rlp_bytes(b"dog")])), "c88363617483646f67");
        assert_eq!(hex(&rlp_bytes(b"")), "80");
        assert_eq!(hex(&rlp_list(&[])), "c0");
        assert_eq!(hex(&rlp_uint(0)), "80", "zero is the empty string, never a zero byte");
        assert_eq!(hex(&rlp_bytes(&[0])), "00", "the byte zero is itself");
        assert_eq!(hex(&rlp_uint(15)), "0f");
        assert_eq!(hex(&rlp_uint(1024)), "820400");
        assert_eq!(hex(&rlp_uint(127)), "7f");
        assert_eq!(hex(&rlp_uint(128)), "8180", "0x80 needs its length byte");
        let lorem = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit";
        assert_eq!(hex(&rlp_bytes(lorem))[..4], *"b838", "a 56-byte string takes the long form");
        assert_eq!(rlp_bytes(&[7u8; 55])[0], 0x80 + 55, "55 bytes is the last short form");
        assert_eq!(&rlp_bytes(&[7u8; 300])[..3], &[0xb9, 0x01, 0x2c], "a 300-byte string names its length in two bytes");
        // the set-theoretic representation of three: [ [], [[]], [ [], [[]] ] ]
        let (e, ee) = (rlp_list(&[]), rlp_list(&[rlp_list(&[])]));
        assert_eq!(hex(&rlp_list(&[e.clone(), ee.clone(), rlp_list(&[e, ee])])), "c7c0c1c0c3c0c1c0");
        // a signature word with leading zeros is the shorter integer, never padded
        let mut w = [0u8; 32];
        w[30] = 0x04;
        assert_eq!(hex(&rlp_word(&w)), "820400");
    }

    /// ⭐ THE NODE'S SIGNED TRANSACTION IS THE ONE ETHEREUM'S OWN TOOLING SIGNS. The raw bytes on the right were made
    /// by Foundry's `cast mktx` (2026-11-11) from the same key and the same fields; the deployment address is the one
    /// `cast compute-address` gives. A wrong byte here is a transaction no Ethereum node will carry.
    /// The key (`eth_vault/tx_key.hex`) is Foundry's own published test account 0: a test value that holds nothing.
    #[test]
    fn a_signed_transaction_is_the_one_ethereums_own_tooling_signs() {
        let key: [u8; 32] = unhex(include_str!("eth_vault/tx_key.hex")).try_into().expect("32 bytes");
        let sender = crate::eth_vault::address_of_secret(&key).expect("a valid key");
        let mut to = [0u8; 20];
        to[19] = 0xa1;
        let call = Tx1559 {
            chain_id: 31337,
            nonce: 7,
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 40_000_000_000,
            gas_limit: 250_000,
            to: Some(to),
            value: 1_000_000_000_000_000,
            data: unhex("b214faa5fe3512ac7ec49225fb90a70a4c83f7ea31b092059f7d589a71e7e7865ba88a1e"),
        };
        let raw = call.sign(&key).expect("a valid key signs");
        assert_eq!(hex(&raw), include_str!("eth_vault/tx_call.hex").trim(), "the signed call");
        assert_eq!(hex(&tx_hash(&raw)), include_str!("eth_vault/tx_call_hash.hex").trim(), "its hash");
        let create = Tx1559 { nonce: 0, to: None, value: 0, data: unhex("60806040525f80fd"), ..call.clone() };
        assert_eq!(hex(&create.sign(&key).expect("signs")), include_str!("eth_vault/tx_create.hex").trim(), "the signed deployment");
        assert_eq!(hex(&created_address(&sender, 0)), include_str!("eth_vault/tx_created.hex").trim().to_lowercase(), "the address it creates");
        // TAMPER: another chain, another nonce or another fee is another digest, so the signature does not carry over
        for (what, other) in [
            ("another chain", Tx1559 { chain_id: 1, ..call.clone() }),
            ("another nonce", Tx1559 { nonce: 8, ..call.clone() }),
            ("another fee", Tx1559 { max_fee_per_gas: 40_000_000_001, ..call.clone() }),
            ("another recipient", Tx1559 { to: Some([0xb2; 20]), ..call.clone() }),
            ("another value", Tx1559 { value: 1_000_000_000_000_001, ..call.clone() }),
            ("other data", Tx1559 { data: vec![0xb2], ..call.clone() }),
        ] {
            assert_ne!(other.signing_digest(), call.signing_digest(), "⛔ {what} is signed by the same digest");
        }
        assert_eq!(call.max_cost_wei(), Some(250_000u128 * 40_000_000_000 + 1_000_000_000_000_000));
        assert_eq!(Tx1559 { max_fee_per_gas: u128::MAX, ..call }.max_cost_wei(), None, "an overflowing cost has no figure, never a wrapped one");
    }
}
