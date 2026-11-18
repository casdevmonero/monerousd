// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ THE ETHEREUM VAULT, THE NODE'S SIDE (docs/BRIDGE-MORE-COINS-SPEC-20261110.md §3.1; user 2026-11-10/11: the bridge
//! widens to Ethereum, Zcash and Solana, and "if the btc and xmr bridge get stronger and more secure, so do those as
//! well automatically").
//!
//! WHAT THIS IS. The ether the bridge holds sits in `IonVault` (`contracts/eth/src/IonVault.sol`), a contract with no
//! owner, no pause and no upgrade, that pays out or hands over only on the signed bond weight of its current custody
//! set. This module is every value a node must compute EXACTLY as that contract does: the signer set's hash, the digest
//! a custodian signs for a payout batch or a hand-over, a deposit's one-time address, the bytes of each call, and the
//! check the contract will run on a set of signatures. It is arithmetic only: it reads no chain, holds no key, moves no
//! value and admits no outside bytes into consensus (it is not a door, §9.6).
//!
//! THE CUSTODY SET IS THE BITCOIN VAULT'S, BY CONSTRUCTION ([`signer_set`]). A vault's Ethereum signers are derived
//! from the SAME registered custody points and the SAME bond weights its Bitcoin leaf is built from
//! (`btc_tx::custody_leaf`), through the SAME slot rule (`btc_tx::custody_slots`: each member's share of sixty slots,
//! quorum two thirds of the slots). So there is no second registration, no second membership and no second quorum rule
//! to drift: a custodian that bonds, leaves or is slashed changes the Ethereum signer set exactly as it changes the
//! Bitcoin leaf, and a stricter rule written there is the rule here.
//!
//! ONE KEY PER CHAIN, FROM ONE REGISTERED POINT ([`custodian_address`], [`custodian_signing_key`]). A custodian's
//! Ethereum key is its registered custody point plus a PUBLIC tweak (`Q = P + t·G`, `t` a hash of `P` under this
//! module's own domain), so every node derives the address from the chain alone and only the custodian can sign for it.
//! The custodian therefore never uses one secret under two signature schemes: Bitcoin's leaf is signed by `d` (BIP-340)
//! and Ethereum's vault by `d + t`. BORROWED: BIP-32's public (non-hardened) child derivation and BIP-341's key tweak.
//!
//! ATOMS. Ether has eighteen decimals and a note's amount is 64 bits, which would cap one note at 18.4 ether. The coin
//! ledger therefore counts GWEI ([`WEI_PER_ATOM`]): one ledger atom is 10^9 wei, a note holds up to 18.4 billion ether,
//! a payout is `atoms × 10^9` wei exactly, and a deposit is credited `wei / 10^9` atoms rounded DOWN, the remainder
//! (under one gwei) staying in the vault as surplus the ledger never counts.
//!
//! SCALE (§9.6 question 7). One vault's signer set is at most [`SIGNERS_MAX`] custodians (`custody_vaults::VAULT_MAX`)
//! whatever the number of nodes that bond; more nodes are more vaults. A payout call is bounded by [`PAYOUTS_MAX`]
//! payouts and [`SWEEP_TAGS_MAX`] swept deposits, so its gas is a constant bound (under 8 million at every bound, a
//! quarter of an Ethereum block) and never a function of the bonded set, the deposits in flight or height. Nothing here
//! is stored.
//!
//! AI RESISTANT (§9.6 question 8). What protects the ether is (c) keys, as a THRESHOLD and never one: two thirds of a
//! vault's bond weight, each custodian signing only a digest its own node rebuilt from its own chain ([`pay_digest`],
//! [`rotate_digest`]), bounded by the vault's bond cover (`custody_vaults::cover`). Ethereum offers a contract nothing
//! stronger than its own signature check; a break of that check is Ethereum's own break and is outside the charter.
//! A lying caller gains nothing: the contract recomputes every hash from the call's own arguments, and
//! [`signed_weight`] is the same check run by the node before anything is broadcast.
//!
//! CLASSICAL-BRIDGE-ENDPOINT: this module signs and recovers Ethereum's own signature, because an Ethereum contract
//! can check nothing else. It is the foreign chain's endpoint; nothing of the MoneroUSD base layer rests on it. Every
//! line that touches the curve is marked `CLASSICAL-CRYPTO-EXEMPT` so it stays greppable.
//!
//! BORROWED: Safe's `checkNSignatures` (ascending signers, low-s, recovered addresses); Axelar's weighted signer set
//! kept as one hash; EIP-1014 (CREATE2) for one-time deposit addresses; EIP-55 for the address text people type.
//! Cons, quantified: none on our chain (0 bytes in any block, nothing at rest). On Ethereum: one signature check per
//! signer in the quorum (about 6,000 gas each, sixteen at most) plus about 60,000 gas per payout, repaid to the caller
//! from the vault inside the cap every signer signed.

use k256::elliptic_curve::ops::Reduce; // CLASSICAL-CRYPTO-EXEMPT: reducing a public tweak to a scalar of Ethereum's curve (bridge endpoint)
use k256::elliptic_curve::point::DecompactPoint; // CLASSICAL-CRYPTO-EXEMPT: lifting a registered custody point from its x (bridge endpoint)
use k256::elliptic_curve::sec1::ToEncodedPoint; // CLASSICAL-CRYPTO-EXEMPT: reading a curve point's coordinates for an Ethereum address (bridge endpoint)
use k256::elliptic_curve::PrimeField; // CLASSICAL-CRYPTO-EXEMPT: a secret's bytes as a scalar of Ethereum's curve (bridge endpoint)
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar, U256}; // CLASSICAL-CRYPTO-EXEMPT: Ethereum's own curve, used only at the vault's endpoint
use sha3::{Digest, Keccak256};

/// An Ethereum address: the last twenty bytes of the Keccak-256 of a public key.
pub type Address = [u8; 20];

/// Wei in one ledger atom: the coin ledger counts gwei (see the module's ATOMS paragraph).
pub const WEI_PER_ATOM: u128 = 1_000_000_000;
/// The most custodians in one vault's signer set: one custody vault (`custody_vaults::VAULT_MAX`).
pub const SIGNERS_MAX: usize = crate::custody_vaults::VAULT_MAX;
/// The most payouts one `pay` call carries. At about 60,000 gas each (a recorded id, a transfer given 30,000 gas, an
/// event) sixty-four payouts are under 4 million gas.
pub const PAYOUTS_MAX: usize = 64;
/// The most waiting deposits one call sweeps. At about 45,000 gas each (a CREATE2 and the forwarder's hand-over)
/// sixty-four sweeps are under 3 million gas.
pub const SWEEP_TAGS_MAX: usize = 64;

/// `keccak256(type(Forwarder).creationCode)` of the contract as compiled by `contracts/eth/foundry.toml` (solc 0.8.26,
/// optimizer 200 runs, no metadata hash, so only a change of the forwarder's CODE moves it). Every deposit address is a
/// CREATE2 address over this hash; `the_values_the_contract_printed` holds it to the compiler's own output.
pub const FORWARDER_CODE_HASH: [u8; 32] = [
    0xf4, 0xcd, 0x84, 0xa2, 0x95, 0xdd, 0xef, 0xcc, 0xb0, 0x2b, 0x7b, 0x71, 0x05, 0x0e, 0xe4, 0x20, 0x8a, 0xc9, 0x10, 0x17, 0x6a, 0xae, 0x72, 0xb3, 0x1f, 0x33,
    0xde, 0x87, 0x14, 0x29, 0x5e, 0x36,
];

/// Sixty-four lower-case hex digits as thirty-two bytes, at compile time (a constant typed wrongly does not build).
const fn hex32(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("a code hash is lower-case hex"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64, "a code hash is thirty-two bytes");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// `keccak256` of the vault's RUNTIME code (the code that sits at a deployed vault's address), as compiled by
/// `contracts/eth/foundry.toml`. The contract has no immutable, so every deployed vault has exactly this code and
/// differs only in the signer set its constructor stored. A custodian reads the code at a vault's address from its own
/// source and compares its hash with this before it trusts a word that address says (`eth_rpc::code_hash_finalized`):
/// a look-alike contract with one more way to move ether has another hash.
pub const VAULT_RUNTIME_CODE_HASH: [u8; 32] = hex32("7dc75ca8edb09326bf2b5100dbd660f64a0760f8daf5e433584adad0182d8d32");
/// `keccak256` of the vault's CREATION code ([`vault_creation_code`] is checked against it before it is ever sent).
pub const VAULT_CREATION_CODE_HASH: [u8; 32] = hex32("300d008da0efcf85ae186a86e29cb761eeb9840432e2e4db70f5cd4c802c58e7");

/// ⭐ THE VAULT'S CREATION CODE: the bytes a deployment sends, as the pinned compiler produced them
/// (`src/eth_vault/ionvault_creation.hex`, 7,474 bytes; `forge build` in `contracts/eth` reproduces them). `None` if the
/// embedded bytes do not hash to [`VAULT_CREATION_CODE_HASH`]: a node never deploys code it cannot name.
#[must_use]
pub fn vault_creation_code() -> Option<Vec<u8>> {
    let h = include_str!("eth_vault/ionvault_creation.hex").trim_ascii().as_bytes();
    if h.len() % 2 != 0 {
        return None;
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    };
    let mut code = Vec::with_capacity(h.len() / 2);
    for pair in h.chunks(2) {
        code.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    (keccak(&code) == VAULT_CREATION_CODE_HASH).then_some(code)
}

/// ⭐ THE DATA OF A VAULT'S DEPLOYMENT for custody set `set`: the creation code followed by the constructor's one
/// argument (`abi.encode(set)`). The vault it creates stores `set.hash(0)` and nothing else. `None` for a set the
/// contract's constructor would refuse.
#[must_use]
pub fn deploy_data(set: &SignerSet) -> Option<Vec<u8>> {
    if !set.well_formed() {
        return None;
    }
    let mut data = vault_creation_code()?;
    data.extend_from_slice(&word_len(32));
    data.extend_from_slice(&set.tuple());
    Some(data)
}

/// The upper bound of a signature's `s` the contract takes (half the curve order): a signature above it has a twin
/// below it, so only the lower is valid and a signature cannot be re-encoded into a second valid one.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9,
    0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// The four-byte selectors of the vault's calls (`the_values_the_contract_printed` holds each to its signature's hash).
pub const PAY_SELECTOR: [u8; 4] = [0xc3, 0x49, 0x50, 0x4d];
pub const ROTATE_SELECTOR: [u8; 4] = [0x7b, 0x8d, 0x34, 0xea];
pub const SWEEP_SELECTOR: [u8; 4] = [0x68, 0x52, 0x16, 0x8a];
pub const DEPOSIT_SELECTOR: [u8; 4] = [0xb2, 0x14, 0xfa, 0xa5];
pub const COLLECT_SELECTOR: [u8; 4] = [0xe5, 0x22, 0x53, 0x81];

/// Keccak-256, Ethereum's hash.
#[must_use]
pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// A number as one 32-byte big-endian ABI word.
fn word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// An address as one ABI word (left-padded with zeros).
fn word_addr(a: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// A count or an offset as one ABI word.
fn word_len(n: usize) -> [u8; 32] {
    word(n as u128)
}

/// The custody set of one vault as the contract takes it: addresses strictly ascending, one weight each, and the signed
/// weight a call needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerSet {
    /// O1-FOOTPRINT-REVIEWED: at most `SIGNERS_MAX` (one custody vault), checked by `well_formed`.
    pub signers: Vec<Address>,
    /// O1-FOOTPRINT-REVIEWED: one per signer.
    pub weights: Vec<u128>,
    pub threshold: u128,
}

impl SignerSet {
    /// The sum of the weights; `None` on overflow (no set a node builds overflows: weights are slot counts).
    #[must_use]
    pub fn total(&self) -> Option<u128> {
        self.weights.iter().try_fold(0u128, |a, w| a.checked_add(*w))
    }

    /// The contract's `_checkShape`, plus this node's own bound on the set's size: ascending distinct non-zero
    /// addresses, a positive weight each, and a threshold above half of the total and at most the total.
    #[must_use]
    pub fn well_formed(&self) -> bool {
        if self.signers.is_empty() || self.signers.len() != self.weights.len() || self.signers.len() > SIGNERS_MAX {
            return false;
        }
        if self.signers[0] == [0u8; 20] || !self.signers.windows(2).all(|w| w[0] < w[1]) || self.weights.contains(&0) {
            return false;
        }
        match (self.total(), self.threshold.checked_mul(2)) {
            (Some(total), Some(twice)) => twice > total && self.threshold <= total,
            _ => false,
        }
    }

    /// The two arrays as ABI tails: `len ‖ items` for the signers, then for the weights.
    fn arrays(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 * (self.signers.len() + 1));
        out.extend_from_slice(&word_len(self.signers.len()));
        for a in &self.signers {
            out.extend_from_slice(&word_addr(a));
        }
        out.extend_from_slice(&word_len(self.weights.len()));
        for w in &self.weights {
            out.extend_from_slice(&word(*w));
        }
        out
    }

    /// `keccak256(abi.encode(signers, weights, threshold, epoch))`: the one word the vault stores for its custody set.
    #[must_use]
    pub fn hash(&self, epoch: u64) -> [u8; 32] {
        let n = self.signers.len();
        let mut enc = Vec::with_capacity(32 * (6 + 2 * n));
        enc.extend_from_slice(&word_len(4 * 32));
        enc.extend_from_slice(&word_len(4 * 32 + 32 * (1 + n)));
        enc.extend_from_slice(&word(self.threshold));
        enc.extend_from_slice(&word(u128::from(epoch)));
        enc.extend_from_slice(&self.arrays());
        keccak(&enc)
    }

    /// The set as a call argument (a dynamic tuple): two offsets, the threshold, then the arrays.
    fn tuple(&self) -> Vec<u8> {
        let n = self.signers.len();
        let mut enc = Vec::with_capacity(32 * (5 + 2 * n));
        enc.extend_from_slice(&word_len(3 * 32));
        enc.extend_from_slice(&word_len(3 * 32 + 32 * (1 + n)));
        enc.extend_from_slice(&word(self.threshold));
        enc.extend_from_slice(&self.arrays());
        enc
    }
}

/// One payout: the id the chain derived from the burn that owes it, who is paid, and how much (wei).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payout {
    pub id: [u8; 32],
    pub to: Address,
    pub wei: u128,
}

/// One custodian's signature as the contract takes it: its place in the signer list and the signature's three parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sig {
    pub index: u32,
    pub v: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// `payouts` as an ABI array of static tuples: `len ‖ (id, to, amount)…`.
fn payouts_array(payouts: &[Payout]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * (1 + 3 * payouts.len()));
    out.extend_from_slice(&word_len(payouts.len()));
    for p in payouts {
        out.extend_from_slice(&p.id);
        out.extend_from_slice(&word_addr(&p.to));
        out.extend_from_slice(&word(p.wei));
    }
    out
}

/// `tags` as an ABI array of words: `len ‖ tag…`.
fn tags_array(tags: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * (1 + tags.len()));
    out.extend_from_slice(&word_len(tags.len()));
    for t in tags {
        out.extend_from_slice(t);
    }
    out
}

/// `sigs` as an ABI array of static tuples: `len ‖ (index, v, r, s)…`.
fn sigs_array(sigs: &[Sig]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * (1 + 4 * sigs.len()));
    out.extend_from_slice(&word_len(sigs.len()));
    for g in sigs {
        out.extend_from_slice(&word(u128::from(g.index)));
        out.extend_from_slice(&word(u128::from(g.v)));
        out.extend_from_slice(&g.r);
        out.extend_from_slice(&g.s);
    }
    out
}

/// `keccak256(abi.encode(payouts))`.
#[must_use]
pub fn payouts_hash(payouts: &[Payout]) -> [u8; 32] {
    let mut enc = word_len(32).to_vec();
    enc.extend_from_slice(&payouts_array(payouts));
    keccak(&enc)
}

/// `keccak256(abi.encode(tags))`.
#[must_use]
pub fn tags_hash(tags: &[[u8; 32]]) -> [u8; 32] {
    let mut enc = word_len(32).to_vec();
    enc.extend_from_slice(&tags_array(tags));
    keccak(&enc)
}

/// ⭐ THE DIGEST A CUSTODIAN SIGNS FOR A PAYOUT BATCH: it binds the Ethereum chain, this one vault, the custody set's
/// epoch, every payout (id, recipient, amount), every deposit swept in passing and the most the caller may be repaid
/// for gas. A signature over it is useless on another chain, another vault, after a hand-over, or for any other batch.
#[must_use]
pub fn pay_digest(chain_id: u64, vault: &Address, epoch: u64, payouts: &[Payout], sweep_tags: &[[u8; 32]], refund_cap_wei: u128) -> [u8; 32] {
    let mut enc = Vec::with_capacity(7 * 32);
    enc.extend_from_slice(&keccak(b"MoneroUSD IonVault pay v1"));
    enc.extend_from_slice(&word(u128::from(chain_id)));
    enc.extend_from_slice(&word_addr(vault));
    enc.extend_from_slice(&word(u128::from(epoch)));
    enc.extend_from_slice(&payouts_hash(payouts));
    enc.extend_from_slice(&tags_hash(sweep_tags));
    enc.extend_from_slice(&word(refund_cap_wei));
    keccak(&enc)
}

/// ⭐ THE DIGEST THE CURRENT SET SIGNS TO HAND THE VAULT TO THE NEXT SET: it binds the chain, the vault, the current
/// epoch and the next set's hash at the next epoch.
#[must_use]
pub fn rotate_digest(chain_id: u64, vault: &Address, epoch: u64, next: &SignerSet) -> [u8; 32] {
    let mut enc = Vec::with_capacity(5 * 32);
    enc.extend_from_slice(&keccak(b"MoneroUSD IonVault rotate v1"));
    enc.extend_from_slice(&word(u128::from(chain_id)));
    enc.extend_from_slice(&word_addr(vault));
    enc.extend_from_slice(&word(u128::from(epoch)));
    enc.extend_from_slice(&next.hash(epoch.saturating_add(1)));
    keccak(&enc)
}

/// ⭐ A DEPOSIT'S ONE-TIME ADDRESS: the CREATE2 address of the vault's forwarder with the deposit's tag as salt. A pure
/// function of the vault and the tag, so any node derives it with no call and a depositor sends a plain transfer from
/// any wallet or exchange. Only the vault can ever deploy code there, and that code can only hand the ether to the vault.
#[must_use]
pub fn deposit_address(vault: &Address, tag: &[u8; 32]) -> Address {
    let mut pre = Vec::with_capacity(85);
    pre.push(0xff);
    pre.extend_from_slice(vault);
    pre.extend_from_slice(tag);
    pre.extend_from_slice(&FORWARDER_CODE_HASH);
    let h = keccak(&pre);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}

/// The bytes of `pay(payouts, sweepTags, refundCap, set, sigs)`. `None` past this module's bounds (a batch over
/// [`PAYOUTS_MAX`], more sweeps than [`SWEEP_TAGS_MAX`], a set that is not well formed, more signatures than signers):
/// a call the node would not want mined is never built.
#[must_use]
pub fn pay_calldata(payouts: &[Payout], sweep_tags: &[[u8; 32]], refund_cap_wei: u128, set: &SignerSet, sigs: &[Sig]) -> Option<Vec<u8>> {
    if payouts.is_empty() || payouts.len() > PAYOUTS_MAX || sweep_tags.len() > SWEEP_TAGS_MAX || !set.well_formed() || sigs.len() > set.signers.len() {
        return None;
    }
    let (p, t, s, g) = (payouts_array(payouts), tags_array(sweep_tags), set.tuple(), sigs_array(sigs));
    let head = 5 * 32;
    let mut out = Vec::with_capacity(4 + head + p.len() + t.len() + s.len() + g.len());
    out.extend_from_slice(&PAY_SELECTOR);
    out.extend_from_slice(&word_len(head));
    out.extend_from_slice(&word_len(head + p.len()));
    out.extend_from_slice(&word(refund_cap_wei));
    out.extend_from_slice(&word_len(head + p.len() + t.len()));
    out.extend_from_slice(&word_len(head + p.len() + t.len() + s.len()));
    out.extend_from_slice(&p);
    out.extend_from_slice(&t);
    out.extend_from_slice(&s);
    out.extend_from_slice(&g);
    Some(out)
}

/// The bytes of `rotate(next, set, sigs)`. `None` when either set is not well formed or there are more signatures than
/// signers.
#[must_use]
pub fn rotate_calldata(next: &SignerSet, set: &SignerSet, sigs: &[Sig]) -> Option<Vec<u8>> {
    if !next.well_formed() || !set.well_formed() || sigs.len() > set.signers.len() {
        return None;
    }
    let (n, s, g) = (next.tuple(), set.tuple(), sigs_array(sigs));
    let head = 3 * 32;
    let mut out = Vec::with_capacity(4 + head + n.len() + s.len() + g.len());
    out.extend_from_slice(&ROTATE_SELECTOR);
    out.extend_from_slice(&word_len(head));
    out.extend_from_slice(&word_len(head + n.len()));
    out.extend_from_slice(&word_len(head + n.len() + s.len()));
    out.extend_from_slice(&n);
    out.extend_from_slice(&s);
    out.extend_from_slice(&g);
    Some(out)
}

/// The bytes of `sweep(tags)`: bring the ether waiting at these deposits' one-time addresses into the vault. Anyone may
/// send it; it can only move ether in. `None` for no tags or more than [`SWEEP_TAGS_MAX`].
#[must_use]
pub fn sweep_calldata(tags: &[[u8; 32]]) -> Option<Vec<u8>> {
    if tags.is_empty() || tags.len() > SWEEP_TAGS_MAX {
        return None;
    }
    let mut out = SWEEP_SELECTOR.to_vec();
    out.extend_from_slice(&word_len(32));
    out.extend_from_slice(&tags_array(tags));
    Some(out)
}

/// The bytes of `deposit(tag)`: a deposit made by a direct call from a wallet that can attach data.
#[must_use]
pub fn deposit_calldata(tag: &[u8; 32]) -> Vec<u8> {
    let mut out = DEPOSIT_SELECTOR.to_vec();
    out.extend_from_slice(tag);
    out
}

// ════════════════════════════════ KEYS, ADDRESSES AND SIGNATURES ════════════════════════════════

/// The address of a curve point: the last twenty bytes of the Keccak-256 of its two coordinates.
fn address_of_point(p: &ProjectivePoint) -> Address {
    let enc = p.to_affine().to_encoded_point(false); // CLASSICAL-CRYPTO-EXEMPT: the uncompressed point an Ethereum address is the hash of (bridge endpoint)
    let h = keccak(&enc.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}

/// A secret's bytes as a non-zero scalar; `None` for zero or a value at or above the curve order (never reduced, so two
/// byte strings are never one key).
fn scalar_of_secret(secret: &[u8; 32]) -> Option<Scalar> {
    let d: Option<Scalar> = Scalar::from_repr(FieldBytes::clone_from_slice(secret)).into(); // CLASSICAL-CRYPTO-EXEMPT: a signing secret as a scalar of Ethereum's curve (bridge endpoint)
    d.filter(|d| !bool::from(d.is_zero()))
}

/// The public tweak that turns a registered custody point (by its x) into that custodian's Ethereum key: a hash of the
/// point under this module's own domain, reduced to a scalar.
fn custody_tweak(custody_x: &[u8; 32]) -> Scalar {
    let t = blake3::derive_key("MonerousD ethereum custody signer v1", custody_x);
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::clone_from_slice(&t)) // CLASSICAL-CRYPTO-EXEMPT: the public tweak as a scalar of Ethereum's curve (bridge endpoint)
}

/// The registered custody point with this x and even y (BIP-340's `lift_x`, the point the Bitcoin leaf names).
fn lift_x(x: &[u8; 32]) -> Option<ProjectivePoint> {
    let p: Option<AffinePoint> = AffinePoint::decompact(FieldBytes::from_slice(x)).into(); // CLASSICAL-CRYPTO-EXEMPT: lifting the registered custody point (bridge endpoint)
    p.map(ProjectivePoint::from)
}

/// ⭐ A CUSTODIAN'S ETHEREUM ADDRESS, from its registered custody point alone (`Q = P + t·G`): what every node computes
/// from the chain's validator set. `None` for an x that is not on the curve (no registered point is).
#[must_use]
pub fn custodian_address(custody_x: &[u8; 32]) -> Option<Address> {
    let q = lift_x(custody_x)? + ProjectivePoint::GENERATOR * custody_tweak(custody_x); // CLASSICAL-CRYPTO-EXEMPT: the custodian's Ethereum key as a public tweak of its registered point (bridge endpoint)
    if q == ProjectivePoint::IDENTITY {
        return None;
    }
    Some(address_of_point(&q))
}

/// ⭐ THE SECRET A CUSTODIAN SIGNS ETHEREUM CALLS WITH, from the secret behind its registered custody point: `d + t`,
/// with `d` negated first when its point has odd y (the registered point is named by its x, BIP-340's convention), so
/// `address_of_secret(custodian_signing_key(d)) == custodian_address(x(d·G))`. `None` for a secret that is not a valid
/// scalar.
#[must_use]
pub fn custodian_signing_key(custody_secret: &[u8; 32]) -> Option<[u8; 32]> {
    let d = scalar_of_secret(custody_secret)?;
    let p = ProjectivePoint::GENERATOR * d; // CLASSICAL-CRYPTO-EXEMPT: the custodian's registered point from its own secret (bridge endpoint)
    let enc = p.to_affine().to_encoded_point(true); // CLASSICAL-CRYPTO-EXEMPT: the point's x and parity (bridge endpoint)
    let b = enc.as_bytes();
    let x: [u8; 32] = b.get(1..33)?.try_into().ok()?;
    let d_even = if b[0] == 0x03 { -d } else { d }; // CLASSICAL-CRYPTO-EXEMPT: the secret of the even-y point the chain registers (bridge endpoint)
    let q = d_even + custody_tweak(&x); // CLASSICAL-CRYPTO-EXEMPT: the tweaked secret (bridge endpoint)
    if bool::from(q.is_zero()) {
        return None;
    }
    Some(q.to_bytes().into())
}

/// The address a secret signs for (`keccak(d·G)`), `None` for a secret that is not a valid scalar.
#[must_use]
pub fn address_of_secret(secret: &[u8; 32]) -> Option<Address> {
    Some(address_of_point(&(ProjectivePoint::GENERATOR * scalar_of_secret(secret)?))) // CLASSICAL-CRYPTO-EXEMPT: an Ethereum address from its secret (bridge endpoint)
}

/// ⭐ THE SIGNER SET OF A VAULT, from its members as the chain seats them (`(registered custody x, bond weight)`, the
/// very list `btc_tx::custody_leaf` takes): each member's Ethereum address, its weight in slots by the Bitcoin leaf's
/// own rule, the threshold that rule gives (two thirds of the slots, rounded up), in ascending address order. `None`
/// for an empty set, more than [`SIGNERS_MAX`] members, a point that is not on the curve, or a set the contract would
/// refuse.
#[must_use]
pub fn signer_set(members: &[([u8; 32], u128)]) -> Option<SignerSet> {
    let mut sorted: Vec<([u8; 32], u128)> = members.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted.dedup_by(|a, b| a.0 == b.0);
    if sorted.is_empty() || sorted.len() > SIGNERS_MAX {
        return None;
    }
    let weights: Vec<u128> = sorted.iter().map(|m| m.1).collect();
    let (slots, k) = crate::btc_tx::custody_slots(&weights)?;
    let mut rows: Vec<(Address, u128)> = Vec::with_capacity(sorted.len());
    for (m, s) in sorted.iter().zip(slots.iter()) {
        rows.push((custodian_address(&m.0)?, u128::from(*s)));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let set = SignerSet { signers: rows.iter().map(|r| r.0).collect(), weights: rows.iter().map(|r| r.1).collect(), threshold: u128::from(k) };
    set.well_formed().then_some(set)
}

/// Is `s` at or under half the curve order (the only form the contract takes)?
fn low_s(s: &[u8; 32]) -> bool {
    s <= &HALF_ORDER
}

/// ⭐ SIGN A DIGEST THE WAY THE VAULT CHECKS IT: Ethereum's signature with a deterministic nonce (RFC 6979), `s` in the
/// lower half, `v` 27 or 28. Returns `(v, r, s)`; `None` for a secret that is not a valid scalar.
#[must_use]
pub fn sign(secret: &[u8; 32], digest: &[u8; 32]) -> Option<(u8, [u8; 32], [u8; 32])> {
    let sk = k256::ecdsa::SigningKey::from_bytes(FieldBytes::from_slice(secret)).ok()?; // CLASSICAL-CRYPTO-EXEMPT: the custodian's Ethereum signing key; an Ethereum contract checks this signature and nothing else (bridge endpoint)
    let (sig, recid) = sk.sign_prehash_recoverable(digest).ok()?; // CLASSICAL-CRYPTO-EXEMPT: Ethereum's own signature over the vault's digest (bridge endpoint)
    let (sig, recid) = match sig.normalize_s() {
        // CLASSICAL-CRYPTO-EXEMPT: the lower-half twin of a signature and its flipped recovery bit (bridge endpoint)
        Some(low) => (low, k256::ecdsa::RecoveryId::from_byte(recid.to_byte() ^ 1)?), // CLASSICAL-CRYPTO-EXEMPT: recovery bit of the lower-half twin (bridge endpoint)
        None => (sig, recid),
    };
    let (r, s): ([u8; 32], [u8; 32]) = (sig.r().to_bytes().into(), sig.s().to_bytes().into());
    if recid.to_byte() > 1 || !low_s(&s) {
        return None;
    }
    Some((27 + recid.to_byte(), r, s))
}

/// ⭐ WHO SIGNED: the contract's `ecrecover`, with the contract's own form rules (`v` 27 or 28, `s` in the lower half).
/// `None` for a signature the contract would refuse or that recovers no key.
#[must_use]
pub fn recover(digest: &[u8; 32], v: u8, r: &[u8; 32], s: &[u8; 32]) -> Option<Address> {
    if !(v == 27 || v == 28) || !low_s(s) {
        return None;
    }
    let sig = k256::ecdsa::Signature::from_scalars(*r, *s).ok()?; // CLASSICAL-CRYPTO-EXEMPT: parsing Ethereum's own signature (bridge endpoint)
    let recid = k256::ecdsa::RecoveryId::from_byte(v - 27)?; // CLASSICAL-CRYPTO-EXEMPT: the signature's recovery bit (bridge endpoint)
    let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(digest, &sig, recid).ok()?; // CLASSICAL-CRYPTO-EXEMPT: recovering the signer of a foreign-chain signature, as the vault's own check does (bridge endpoint)
    let enc = vk.to_encoded_point(false); // CLASSICAL-CRYPTO-EXEMPT: the recovered point's coordinates (bridge endpoint)
    let h = keccak(&enc.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    (a != [0u8; 20]).then_some(a)
}

/// ⭐ THE CONTRACT'S `_checkSigned`, RUN BY THE NODE: the weight of `sigs` over `digest` under `set`, or `None` when the
/// contract would refuse the list outright (a place out of range or not strictly ascending, a signature in the wrong
/// form, or one that does not recover the signer at its place). A node broadcasts a call only when this reaches the
/// set's threshold ([`passes`]), so a call that would revert is never paid for.
#[must_use]
pub fn signed_weight(digest: &[u8; 32], set: &SignerSet, sigs: &[Sig]) -> Option<u128> {
    if !set.well_formed() {
        return None;
    }
    let mut weight = 0u128;
    let mut last: Option<u32> = None;
    for g in sigs {
        let i = g.index as usize;
        if i >= set.signers.len() || last.is_some_and(|l| g.index <= l) {
            return None;
        }
        last = Some(g.index);
        if recover(digest, g.v, &g.r, &g.s)? != set.signers[i] {
            return None;
        }
        weight = weight.checked_add(set.weights[i])?;
    }
    Some(weight)
}

/// Do `sigs` over `digest` reach `set`'s threshold, by the contract's own check?
#[must_use]
pub fn passes(digest: &[u8; 32], set: &SignerSet, sigs: &[Sig]) -> bool {
    signed_weight(digest, set, sigs).is_some_and(|w| w >= set.threshold)
}

// ════════════════════════════════ AMOUNTS AND ADDRESS TEXT ════════════════════════════════

/// The wei a payout of `atoms` ledger atoms sends: exact (64 bits of gwei times 10^9 is under 2^94).
#[must_use]
pub fn wei_of_atoms(atoms: u64) -> u128 {
    u128::from(atoms) * WEI_PER_ATOM
}

/// The ledger atoms a deposit of `wei` is credited: rounded DOWN (the part under one gwei stays in the vault as
/// surplus). `None` when it does not fit a note (above 18.4 billion ether, more than exists).
#[must_use]
pub fn atoms_of_wei(wei: u128) -> Option<u64> {
    u64::try_from(wei / WEI_PER_ATOM).ok()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        s.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
    }
    s
}

/// An address as the text people read: `0x` and forty hex digits with EIP-55's mixed-case checksum.
#[must_use]
pub fn address_text(a: &Address) -> String {
    let lower = hex_lower(a);
    let h = keccak(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (h[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 15;
        out.push(if c.is_ascii_alphabetic() && nibble >= 8 { c.to_ascii_uppercase() } else { c });
    }
    out
}

/// ⭐ A PAYOUT ADDRESS A PERSON TYPED: `0x` and forty hex digits; all lower case or all upper case is taken as it is, and
/// mixed case must be EIP-55's checksum exactly (so one mistyped character is refused instead of paying a stranger).
/// The zero address is refused (the vault refuses to pay it).
#[must_use]
pub fn parse_address(text: &str) -> Option<Address> {
    let hex = text.strip_prefix("0x")?;
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut a = [0u8; 20];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        a[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    if a == [0u8; 20] {
        return None;
    }
    let letters = || hex.bytes().filter(u8::is_ascii_alphabetic);
    let one_case = letters().all(|b| b.is_ascii_lowercase()) || letters().all(|b| b.is_ascii_uppercase());
    (one_case || address_text(&a) == text).then_some(a)
}

#[cfg(test)]
mod eth_vault_tests {
    use super::*;

    fn h32(s: &str) -> [u8; 32] {
        let s = s.trim_start_matches("0x");
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        let s = s.trim_start_matches("0x");
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    fn addr(s: &str) -> Address {
        parse_address(s).unwrap_or_else(|| panic!("{s} is an address"))
    }

    // ── the fixed inputs of contracts/eth/test/Vectors.t.sol and what the contract printed for them ──
    const KEYS: [&str; 3] = [
        "2222222222222222222222222222222222222222222222222222222222222222",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "3333333333333333333333333333333333333333333333333333333333333333",
    ];
    const SIGNERS: [&str; 3] = ["0x1563915e194D8CfBA1943570603F7606A3115508", "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A", "0x5CbDd86a2FA8Dc4bDdd8a8f69dBa48572EeC07FB"];
    const VAULT: &str = "0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f";
    const CHAIN_ID: u64 = 31337;
    const TAG: &str = "fe3512ac7ec49225fb90a70a4c83f7ea31b092059f7d589a71e7e7865ba88a1e";

    fn set() -> SignerSet {
        SignerSet { signers: SIGNERS.iter().map(|s| addr(s)).collect(), weights: vec![5, 3, 2], threshold: 7 }
    }

    fn next_set() -> SignerSet {
        SignerSet { signers: vec![addr(SIGNERS[0]), addr(SIGNERS[2])], weights: vec![4, 6], threshold: 7 }
    }

    fn payouts() -> Vec<Payout> {
        let mut a1 = [0u8; 20];
        a1[19] = 0xa1;
        let mut b2 = [0u8; 20];
        b2[19] = 0xb2;
        vec![
            Payout { id: keccak(b"burn one"), to: a1, wei: 1_000_000_000_000_000_000 },
            Payout { id: keccak(b"burn two"), to: b2, wei: 250_000_000_000_000_000 },
        ]
    }

    fn two_sigs(digest: &[u8; 32]) -> Vec<Sig> {
        (0..2u32)
            .map(|i| {
                let (v, r, s) = sign(&h32(KEYS[i as usize]), digest).expect("a valid key signs");
                Sig { index: i, v, r, s }
            })
            .collect()
    }

    /// ⭐ THE NODE COMPUTES WHAT THE CONTRACT COMPUTES, BYTE FOR BYTE. Every constant on the right was printed by the
    /// compiled contract itself (`forge test --match-contract VectorsTest -vv`, solc 0.8.26) for the inputs above; the
    /// same run then SENT the printed pay call and the printed hand-over to the contract and both were taken. A wrong
    /// word anywhere here is a payout the vault refuses, or a deposit address nobody can sweep.
    #[test]
    fn the_values_the_contract_printed() {
        // keys and addresses
        for (k, a) in KEYS.iter().zip(SIGNERS.iter()) {
            assert_eq!(address_of_secret(&h32(k)).map(|a| address_text(&a)).as_deref(), Some(*a), "the address of a key, in EIP-55 text");
        }
        let (set, vault, tag) = (set(), addr(VAULT), h32(TAG));
        assert!(set.well_formed());
        assert_eq!(tag, keccak(b"deposit tag one"));
        assert_eq!(set.hash(0), h32("1ae21fa9e57b12a70bb3ab9aeb9a99de849855940e555a97c3995ad80419d03c"), "signerSetHash");
        assert_eq!(address_text(&deposit_address(&vault, &tag)), "0xB1B2b5514098C755b1Df8ed70da9f7EEd792DDC8", "depositAddress");
        // the payout batch
        let (pays, tags, cap) = (payouts(), vec![tag], 3_000_000_000_000_000u128);
        assert_eq!(payouts_hash(&pays), h32("cf2ea8e6b53e7c24b77838ce7a3d56b69a2a8937a1ab2f8f17d60b3820a69204"), "payoutsHash");
        assert_eq!(tags_hash(&tags), h32("af17c7f3d18f0f70d207b606dac7bb52a9f8764c4aceecb49a8f75e3a10f3f92"), "tagsHash");
        let digest = pay_digest(CHAIN_ID, &vault, 0, &pays, &tags, cap);
        assert_eq!(digest, h32("c6b0a173f6057e1cb4a523c958454242dd96a02abb6146999d8166b85c19f388"), "payDigest");
        let sigs = two_sigs(&digest);
        assert_eq!((sigs[0].v, sigs[0].r, sigs[0].s), (28, h32("5d39445be2350aaf905f5d618e43097d87a0a70b46c6f59c8dde028fb1c41f36"), h32("615d9934d614dc7e776ac4bcaa8a81e66b064cae612b97290ff81de590967174")));
        assert_eq!((sigs[1].v, sigs[1].r, sigs[1].s), (27, h32("e12391fcb9f6c5c7f56e5fe921261092ceaf8c97be587ddc0a465b12bb354176"), h32("534c535136d6bcaa6348404cdb5f0d1f2921e175f360ee7effefe8b2dcb99ac4")));
        assert_eq!(signed_weight(&digest, &set, &sigs), Some(8));
        assert!(passes(&digest, &set, &sigs));
        assert_eq!(pay_calldata(&pays, &tags, cap, &set, &sigs).map(|c| hex_lower(&c)).as_deref(), Some(PAY_CALLDATA), "payCalldata");
        // the hand-over
        let next = next_set();
        assert_eq!(next.hash(1), h32("39435cbd6ee10cbfe1b290782f2c6b211944910f00c3e71f9ffb841614325860"), "nextSetHash");
        let rdigest = rotate_digest(CHAIN_ID, &vault, 0, &next);
        assert_eq!(rdigest, h32("3e6378f9d17e32d139047052f6c5791d36cdb1492e04b9c122624289a84fac6c"), "rotateDigest");
        let rsigs = two_sigs(&rdigest);
        assert_eq!((rsigs[0].v, rsigs[0].r), (28, h32("6189c6dffd0ed0ec177d731f094bfa644d52481e87b80050c0f507c471ecddb3")));
        assert_eq!((rsigs[1].v, rsigs[1].s), (27, h32("1c57717532590992044dded0a5ee272ebdd8a7746b3b4c17735ddabd3000a1b7")));
        assert_eq!(rotate_calldata(&next, &set, &rsigs).map(|c| hex_lower(&c)).as_deref(), Some(ROTATE_CALLDATA), "rotateCalldata");
        // the small calls and the selectors
        assert_eq!(
            sweep_calldata(&tags).map(|c| hex_lower(&c)).as_deref(),
            Some("6852168a00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001fe3512ac7ec49225fb90a70a4c83f7ea31b092059f7d589a71e7e7865ba88a1e")
        );
        assert_eq!(hex_lower(&deposit_calldata(&tag)), "b214faa5fe3512ac7ec49225fb90a70a4c83f7ea31b092059f7d589a71e7e7865ba88a1e");
        for (sel, sig) in [
            (PAY_SELECTOR, "pay((bytes32,address,uint256)[],bytes32[],uint256,(address[],uint256[],uint256),(uint256,uint8,bytes32,bytes32)[])"),
            (ROTATE_SELECTOR, "rotate((address[],uint256[],uint256),(address[],uint256[],uint256),(uint256,uint8,bytes32,bytes32)[])"),
            (SWEEP_SELECTOR, "sweep(bytes32[])"),
            (DEPOSIT_SELECTOR, "deposit(bytes32)"),
            (COLLECT_SELECTOR, "collect()"),
        ] {
            assert_eq!(sel, keccak(sig.as_bytes())[..4], "{sig}");
        }
        assert_eq!(FORWARDER_CODE_HASH, h32("f4cd84a295ddefccb02b7b71050ee4208ac910176aae72b31f33de8714295e36"), "forwarderCodeHash");
        // the code a deployment sends is the compiler's own, and a deployment for this set is that code and the set
        let code = vault_creation_code().expect("⛔ the embedded creation code does not hash to its constant");
        assert_eq!(code.len(), 7_474, "the vault's creation code, as compiled");
        let data = deploy_data(&set).expect("a well-formed set deploys");
        assert_eq!((&data[..code.len()], data.len()), (&code[..], code.len() + 32 * (1 + 11)), "creation code, then abi.encode(set)");
        assert_eq!(&data[code.len()..code.len() + 32], &word_len(32)[..]);
        assert_eq!(deploy_data(&SignerSet { threshold: 5, ..set.clone() }), None, "⛔ a set a minority could control is never deployed");
        assert_ne!(VAULT_RUNTIME_CODE_HASH, keccak(b""), "a vault's code is not the code of an empty address");
    }

    /// `payCalldata` and `rotateCalldata` as the contract printed them (and then took them), one line of hex each.
    const PAY_CALLDATA: &str = include_str!("eth_vault/pay_calldata.hex").trim_ascii();
    const ROTATE_CALLDATA: &str = include_str!("eth_vault/rotate_calldata.hex").trim_ascii();

    /// ⛔ TAMPER: every way to make a batch say something its signers did not sign is refused by the node's copy of the
    /// contract's check, exactly where the contract refuses it (`contracts/eth/test/IonVault.t.sol` holds the contract
    /// to the same list): another amount, another recipient, another id, another chain, another vault, a later epoch,
    /// a larger refund, one signer counted twice, a signer in the wrong place, a high-s twin, and a minority.
    #[test]
    fn a_batch_its_signers_did_not_sign_is_refused() {
        let (set, vault, tag) = (set(), addr(VAULT), h32(TAG));
        let (pays, tags, cap) = (payouts(), vec![tag], 3_000_000_000_000_000u128);
        let digest = pay_digest(CHAIN_ID, &vault, 0, &pays, &tags, cap);
        let sigs = two_sigs(&digest);
        assert!(passes(&digest, &set, &sigs), "CONTROL: the honest batch passes");
        let mut richer = pays.clone();
        richer[0].wei += 1;
        let mut thief = pays.clone();
        thief[1].to[0] ^= 1;
        let mut other_id = pays.clone();
        other_id[0].id[31] ^= 1;
        let mut other_vault = vault;
        other_vault[19] ^= 1;
        for (what, d) in [
            ("another amount", pay_digest(CHAIN_ID, &vault, 0, &richer, &tags, cap)),
            ("another recipient", pay_digest(CHAIN_ID, &vault, 0, &thief, &tags, cap)),
            ("another payout id", pay_digest(CHAIN_ID, &vault, 0, &other_id, &tags, cap)),
            ("another chain", pay_digest(1, &vault, 0, &pays, &tags, cap)),
            ("another vault", pay_digest(CHAIN_ID, &other_vault, 0, &pays, &tags, cap)),
            ("a later epoch", pay_digest(CHAIN_ID, &vault, 1, &pays, &tags, cap)),
            ("a larger refund", pay_digest(CHAIN_ID, &vault, 0, &pays, &tags, cap + 1)),
            ("no sweep", pay_digest(CHAIN_ID, &vault, 0, &pays, &[], cap)),
        ] {
            assert_ne!(d, digest, "{what} is another digest");
            assert_eq!(signed_weight(&d, &set, &sigs), None, "⛔ {what}: the signatures do not recover the signers");
        }
        // one signer twice, and a signer claimed at another's place
        assert_eq!(signed_weight(&digest, &set, &[sigs[0], sigs[0]]), None, "⛔ one signer counted twice");
        assert_eq!(signed_weight(&digest, &set, &[sigs[1], sigs[0]]), None, "⛔ places out of order");
        assert_eq!(signed_weight(&digest, &set, &[Sig { index: 2, ..sigs[0] }]), None, "⛔ a signature at another signer's place");
        assert_eq!(signed_weight(&digest, &set, &[Sig { index: 3, ..sigs[0] }]), None, "⛔ a place past the set");
        // the high-s twin of a valid signature (s' = n − s, v flipped) recovers the same signer and is refused by form
        let n = hex_bytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let mut twin = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let v = i16::from(n[i]) - i16::from(sigs[0].s[i]) - borrow;
            twin[i] = v.rem_euclid(256) as u8;
            borrow = i16::from(v < 0);
        }
        assert!(!low_s(&twin));
        assert_eq!(recover(&digest, 55 - sigs[0].v, &sigs[0].r, &twin), None, "⛔ the high-s twin");
        assert_eq!(recover(&digest, 29, &sigs[0].r, &sigs[0].s), None, "⛔ a recovery byte the contract refuses");
        // a minority of weight signs a well-formed list that does not pass: the lightest two hold 5 of 10
        let light: Vec<Sig> = [1u32, 2]
            .iter()
            .map(|i| {
                let (v, r, s) = sign(&h32(KEYS[*i as usize]), &digest).unwrap();
                Sig { index: *i, v, r, s }
            })
            .collect();
        assert_eq!(signed_weight(&digest, &set, &light), Some(5));
        assert!(!passes(&digest, &set, &light), "⛔ a minority of bond does not pay");
        // a hand-over signed for one next set does not hand over to another
        let (next, mut other) = (next_set(), next_set());
        other.weights[0] = 6;
        other.weights[1] = 4;
        let rsigs = two_sigs(&rotate_digest(CHAIN_ID, &vault, 0, &next));
        assert!(passes(&rotate_digest(CHAIN_ID, &vault, 0, &next), &set, &rsigs));
        assert_eq!(signed_weight(&rotate_digest(CHAIN_ID, &vault, 0, &other), &set, &rsigs), None, "⛔ another next set");
    }

    /// A set the contract would refuse at creation is not a set here either, and the bounds this module states are the
    /// bounds it enforces: the first size past each is refused (SAFE AT SCALE: the limit and the limit plus one).
    #[test]
    fn a_set_or_a_batch_past_a_bound_is_never_built() {
        let good = set();
        for (what, bad) in [
            ("a minority threshold", SignerSet { threshold: 5, ..good.clone() }),
            ("a threshold above the total", SignerSet { threshold: 11, ..good.clone() }),
            ("a zero weight", SignerSet { weights: vec![5, 0, 5], ..good.clone() }),
            ("signers out of order", SignerSet { signers: vec![good.signers[1], good.signers[0], good.signers[2]], ..good.clone() }),
            ("a signer twice", SignerSet { signers: vec![good.signers[0], good.signers[0], good.signers[2]], ..good.clone() }),
            ("the zero address", SignerSet { signers: vec![[0u8; 20], good.signers[1], good.signers[2]], ..good.clone() }),
            ("weights that do not match", SignerSet { weights: vec![5, 5], ..good.clone() }),
            ("an empty set", SignerSet { signers: vec![], weights: vec![], threshold: 1 }),
        ] {
            assert!(!bad.well_formed(), "⛔ {what}");
            assert_eq!(pay_calldata(&payouts(), &[], 0, &bad, &[]), None, "⛔ {what}: no call is built for it");
        }
        let wide = |n: usize| SignerSet {
            signers: (1..=n as u8).map(|i| [i; 20]).collect(),
            weights: vec![1; n],
            threshold: (2 * n as u128).div_ceil(3),
        };
        assert!(wide(SIGNERS_MAX).well_formed(), "sixteen signers: one full vault");
        assert!(!wide(SIGNERS_MAX + 1).well_formed(), "⛔ seventeen signers are two vaults, never one set");
        let many = |n: usize| vec![payouts()[0]; n];
        assert!(pay_calldata(&many(PAYOUTS_MAX), &[], 0, &good, &[]).is_some());
        assert_eq!(pay_calldata(&many(PAYOUTS_MAX + 1), &[], 0, &good, &[]), None, "⛔ one payout past the batch bound");
        assert_eq!(pay_calldata(&[], &[], 0, &good, &[]), None, "⛔ an empty batch");
        assert!(sweep_calldata(&vec![[7u8; 32]; SWEEP_TAGS_MAX]).is_some());
        assert_eq!(sweep_calldata(&vec![[7u8; 32]; SWEEP_TAGS_MAX + 1]), None, "⛔ one sweep past the bound");
        // the batch at every bound: its bytes are a constant, whatever the number of nodes that bond
        let full = pay_calldata(&many(PAYOUTS_MAX), &vec![[7u8; 32]; SWEEP_TAGS_MAX], 0, &wide(SIGNERS_MAX), &vec![Sig { index: 0, v: 27, r: [1; 32], s: [1; 32] }; SIGNERS_MAX]).unwrap();
        assert_eq!(full.len(), 4 + 32 * (5 + (1 + 3 * PAYOUTS_MAX) + (1 + SWEEP_TAGS_MAX) + (3 + 2 * (1 + SIGNERS_MAX)) + (1 + 4 * SIGNERS_MAX)), "11,684 bytes at every bound");
    }

    /// ⭐ THE ETHEREUM CUSTODY SET IS THE BITCOIN LEAF'S: the same members, each with the slots the leaf gives it and the
    /// leaf's own quorum; a custodian signs for exactly the address every node derives from its registered point; and
    /// no custodian's Ethereum key is its Bitcoin key.
    #[test]
    fn a_vaults_signers_are_its_bitcoin_leafs_members_with_the_leafs_quorum() {
        let secrets: Vec<[u8; 32]> = (1u8..=5).map(|i| *blake3::hash(&[i; 8]).as_bytes()).collect();
        let weights = [400u128, 250, 150, 120, 80];
        let members: Vec<([u8; 32], u128)> = secrets.iter().zip(weights).map(|(s, w)| (crate::btc_tx::xonly_pubkey(s).unwrap(), w)).collect();
        let set = signer_set(&members).expect("five bonded custodians form a set");
        let leaf = crate::btc_tx::custody_leaf(&members).unwrap();
        assert_eq!(set.threshold, u128::from(leaf.k), "the quorum is the Bitcoin leaf's");
        assert_eq!(set.total(), Some(leaf.slot_keys.len() as u128), "the total weight is the leaf's slot count");
        for (secret, (x, _)) in secrets.iter().zip(members.iter()) {
            let a = custodian_address(x).unwrap();
            let i = set.signers.iter().position(|s| *s == a).expect("every member signs");
            assert_eq!(set.weights[i], leaf.slot_keys.iter().filter(|k| *k == x).count() as u128, "its weight is its slots in the leaf");
            let eth_key = custodian_signing_key(secret).unwrap();
            assert_eq!(address_of_secret(&eth_key), Some(a), "the custodian's own secret signs for the address the chain derives");
            assert_ne!(address_of_secret(secret), Some(a), "its Ethereum key is not its Bitcoin key");
            assert_ne!(&eth_key, secret);
        }
        // order-free and member-exact, as the leaf is
        let mut shuffled = members.clone();
        shuffled.reverse();
        assert_eq!(signer_set(&shuffled), Some(set.clone()));
        assert_ne!(signer_set(&members[..4]), Some(set.clone()), "a member fewer is another set");
        // a quorum by the leaf's rule signs a digest the set passes; one slot short does not
        let digest = keccak(b"any digest");
        let mut by_weight: Vec<usize> = (0..set.signers.len()).collect();
        by_weight.sort_by_key(|i| std::cmp::Reverse(set.weights[*i]));
        let sign_as = |i: usize| {
            let secret = secrets.iter().find(|s| address_of_secret(&custodian_signing_key(s).unwrap()) == Some(set.signers[i])).unwrap();
            let (v, r, s) = sign(&custodian_signing_key(secret).unwrap(), &digest).unwrap();
            Sig { index: i as u32, v, r, s }
        };
        let mut picked: Vec<usize> = Vec::new();
        let mut weight = 0u128;
        for i in by_weight {
            if weight >= set.threshold {
                break;
            }
            picked.push(i);
            weight += set.weights[i];
        }
        picked.sort_unstable();
        let sigs: Vec<Sig> = picked.iter().map(|i| sign_as(*i)).collect();
        assert!(passes(&digest, &set, &sigs), "two thirds of the slots pass");
        assert!(!passes(&digest, &set, &sigs[..sigs.len() - 1]), "⛔ without its last signer the same list is under the quorum");
        assert_eq!(signer_set(&[]), None);
        assert_eq!(signer_set(&vec![members[0]; 1]).map(|s| (s.weights, s.threshold)), Some((vec![60], 40)), "a lone custodian holds every slot");
    }

    /// Amounts cross the gwei boundary without creating a wei, and an address a person mistypes is refused.
    #[test]
    fn amounts_round_down_and_a_mistyped_address_is_refused() {
        assert_eq!(wei_of_atoms(1), 1_000_000_000);
        assert_eq!(atoms_of_wei(1_999_999_999), Some(1), "a deposit is credited its whole gwei, the rest stays in the vault");
        assert_eq!(atoms_of_wei(999_999_999), Some(0));
        assert_eq!(atoms_of_wei(wei_of_atoms(u64::MAX)), Some(u64::MAX));
        assert_eq!(atoms_of_wei(wei_of_atoms(u64::MAX) + WEI_PER_ATOM), None, "an amount no note can hold has no atom count");
        for wei in [0u128, 1, 999_999_999, 1_000_000_000, 123_456_789_012_345_678_901] {
            assert!(atoms_of_wei(wei).is_some_and(|a| wei_of_atoms(a) <= wei), "credited atoms never exceed the wei that arrived");
        }
        let good = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"; // EIP-55's own first test address
        let a = parse_address(good).expect("EIP-55's test address");
        assert_eq!(address_text(&a), good);
        assert_eq!(parse_address(&good.to_lowercase()), Some(a), "all lower case carries no checksum and is taken");
        assert_eq!(parse_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"), None, "⛔ one letter's case wrong");
        assert_eq!(parse_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe"), None, "⛔ a digit short");
        assert_eq!(parse_address("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"), None, "⛔ no 0x");
        assert_eq!(parse_address("0x0000000000000000000000000000000000000000"), None, "⛔ the zero address");
        assert_eq!(parse_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeg"), None, "⛔ not hex");
    }
}
