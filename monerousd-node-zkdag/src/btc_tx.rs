// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐⭐ DB-121 (2026-09-20) — THE BITCOIN EXIT LEG'S TRANSACTION LAYER.
//!
//! Until today the peg could take a Bitcoin deposit in and could never pay one out: the burn destroyed the
//! USDm and `mark_released` recorded a release, but nothing in any tree could sign a Bitcoin transaction for
//! the reserve key. This module is that missing half, in the shape the user set: every bonded custodian node
//! signs INDEPENDENTLY and AUTOMATICALLY, any node gathers a quorum, nobody runs a signing session.
//!
//! WHY `OP_CHECKSIGADD` AND NOT A THRESHOLD SIGNATURE. MonerousD's reserve authority is a bond-weighted
//! MULTISIG TALLY of independent ML-DSA-65 signatures (`crate::bond_tally::verify_threshold`) — no key shares,
//! no rounds, no dealer. Bitcoin has exactly that shape natively since Taproot (BIP 342): a tapscript
//! `<pk_1> OP_CHECKSIG <pk_2> OP_CHECKSIGADD … <pk_n> OP_CHECKSIGADD <k> OP_NUMEQUAL` is satisfied by any k
//! of n INDEPENDENT signatures over the same sighash. A custodian signs when it has verified the obligation
//! from its own chain state, gossips its signature, and is done; an aggregate signature would have needed
//! nonce rounds, a dealer or a distributed key generation, and a coordinator whose absence stalls the payout
//! (the liveness trade-off the user refused). Bond weight is carried as key SLOTS (a member with twice the
//! bond holds twice the slots), so the on-chain quorum is the same ≥2/3-of-weight rule the post-quantum tally
//! enforces — see [`custody_slots`].
//!
//! THE KEY PATH IS PROVABLY UNSPENDABLE. The taproot internal key is BIP 341's NUMS point (`lift_x` of
//! `0x50929b…3ac0`, whose discrete logarithm nobody knows) plus a PUBLIC per-deposit tweak, so every deposit
//! gets a fresh address and the ONLY way to move the coins is the script path — the k-of-n. There is no
//! aggregate key, no dealer and no single holder anywhere.
//!
//! CLASSICAL-BRIDGE-ENDPOINT: this is the one module that produces a classical signature, because Bitcoin
//! accepts nothing else — a taproot output is spendable by a BIP-340 signature and by nothing post-quantum.
//! The MonerousD base layer, consensus, wallet and every authority decision stay post-quantum: a custodian
//! signs here ONLY for a burn its post-quantum chain state already finalized. Every classical line below is
//! marked `CLASSICAL-CRYPTO-EXEMPT` so it stays greppable (user 2026-09-20: the guard "must allow external
//! chain work that only allows classical crypto").
//!
//! Borrowed, not derived: the sighash is BIP 341 "common signature message" byte for byte, the leaf hash and
//! taptweak are BIP 341's tagged hashes, the address is BIP 350 bech32m, the script is BIP 342's multisig
//! idiom (`multi_a` in Bitcoin Core's descriptor language). The pins in `tests` are BIP 341's own published
//! vectors, and the regtest oracle test hands the transaction to a real Bitcoin Core for the verdict.

use k256::elliptic_curve::ops::Reduce; // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's secp256k1 scalar reduction for the taproot tweak (bridge endpoint)
use k256::elliptic_curve::point::DecompactPoint; // CLASSICAL-CRYPTO-EXEMPT: BIP-340 x-only key lifting on Bitcoin's curve (bridge endpoint)
use k256::elliptic_curve::sec1::ToEncodedPoint; // CLASSICAL-CRYPTO-EXEMPT: reading a Bitcoin curve point's x and parity (bridge endpoint)
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar, U256}; // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own curve, used only to shape the reserve output (bridge endpoint)
use sha2::{Digest, Sha256};

/// Bitcoin Core's dust threshold for a payout's change: below it the coin costs more to spend than it holds, so
/// the change folds into the fee.
/// PAST-CHATS-CHECKED: Bitcoin Core `policy/policy.h` (`GetDustThreshold` at the default 3 sat/vB dust relay
/// fee gives 546 sats for a P2PKH-sized output; taproot's is lower) — the network's figure, not ours.
pub const DUST_SATS: u64 = 546;
/// BIP 342 tapscript leaf version.
pub const LEAF_VERSION: u8 = 0xc0;
/// BIP 341's "nothing up my sleeve" x-only point: the SHA-256 of the generator's compressed encoding, lifted.
/// Nobody knows its discrete logarithm, so an internal key derived from it has NO key-path spender.
pub const NUMS_X: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a,
    0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];
/// How many key slots a custody leaf spreads the bonded weight over. Sixty divides evenly for every set size
/// up to six and keeps the leaf under ~2 KB, so a payout input's witness stays far inside Bitcoin's standard
/// transaction weight. With equal weights (the free founding seats) every member holds `60 / n` slots and the
/// quorum is exactly `⌈2n/3⌉` members — the same count the post-quantum tally needs. A set larger than sixty
/// adds one slot per extra member (every member keeps at least one).
pub const SLOT_TARGET: u32 = 60;
/// The most reserve coins one payout transaction spends. With sixty slots and forty signatures an input's
/// witness is ~4.7 KB, so thirty-two inputs stay well inside Bitcoin's 400 000-weight standard limit.
pub const PAYOUT_INPUTS_MAX: usize = 32;
/// The widest standard scriptPubKey (P2WSH and P2TR are 34 bytes; P2PKH 25, P2SH 23, P2WPKH 22).
pub const SCRIPT_PUBKEY_MAX: usize = 34;

pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKSIGADD: u8 = 0xba;
pub const OP_NUMEQUAL: u8 = 0x9c;
pub const OP_1: u8 = 0x51;

/// `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)` — BIP 340/341's tagged hash.
pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let th = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(th);
    h.update(th);
    h.update(msg);
    h.finalize().into()
}

pub fn sha256d(b: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(b)).into()
}

fn scalar_of(bytes: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::clone_from_slice(bytes)) // CLASSICAL-CRYPTO-EXEMPT: taptweak scalar on Bitcoin's curve (bridge endpoint)
}

/// BIP 340 `lift_x`: the curve point with this x and EVEN y, or `None` when x is not on the curve.
fn lift_x(x: &[u8; 32]) -> Option<ProjectivePoint> {
    let p: Option<AffinePoint> = AffinePoint::decompact(FieldBytes::from_slice(x)).into(); // CLASSICAL-CRYPTO-EXEMPT: BIP-340 x-only lifting (bridge endpoint)
    p.map(ProjectivePoint::from)
}

/// A point's x-only bytes and whether its y is odd (the parity bit a taproot control block carries).
fn x_and_parity(p: &ProjectivePoint) -> ([u8; 32], bool) {
    let enc = p.to_affine().to_encoded_point(true); // CLASSICAL-CRYPTO-EXEMPT: compressed SEC1 read of a Bitcoin point (bridge endpoint)
    let b = enc.as_bytes();
    let mut x = [0u8; 32];
    x.copy_from_slice(&b[1..33]);
    (x, b[0] == 0x03)
}

/// Bitcoin's compact-size integer.
pub fn compact_size(n: u64, out: &mut Vec<u8>) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Minimal script-number push for the quorum count `k` (BIP 62 minimal encoding, as Bitcoin Core emits).
fn push_scriptnum(k: u32, out: &mut Vec<u8>) {
    if k == 0 {
        out.push(0x00);
        return;
    }
    if k <= 16 {
        out.push(OP_1 + (k as u8 - 1));
        return;
    }
    let mut bytes = [0u8; 5];
    let mut n = 0usize;
    let mut v = k;
    while v > 0 {
        bytes[n] = (v & 0xff) as u8;
        n += 1;
        v >>= 8;
    }
    if bytes[n - 1] & 0x80 != 0 {
        bytes[n] = 0x00;
        n += 1;
    }
    out.push(n as u8);
    out.extend_from_slice(&bytes[..n]);
}

/// Spread bonded weights over [`SLOT_TARGET`] key slots and return `(slots per member, k)` with
/// `k = ⌈2·Σslots/3⌉` — the on-chain twin of the tally's `attested·3 ≥ total·2`.
///
/// Every member holds at least one slot (a member with weight is never silently dropped from the script), so
/// rounding can only ever RAISE a small holder's share by a fraction of one slot; with the equal weights the
/// free founding seats carry the split is exact. A set whose total weight is zero is treated as equal.
#[must_use]
pub fn custody_slots(weights: &[u128]) -> Option<(Vec<u32>, u32)> {
    if weights.is_empty() {
        return None;
    }
    let total: u128 = weights.iter().fold(0u128, |a, w| a.saturating_add(*w));
    let slots: Vec<u32> = if total == 0 {
        vec![1; weights.len()]
    } else {
        weights
            .iter()
            .map(|w| {
                let s = w.saturating_mul(SLOT_TARGET as u128) / total;
                s.clamp(1, SLOT_TARGET as u128) as u32
            })
            .collect()
    };
    let sum: u32 = slots.iter().sum();
    let k = (2 * sum).div_ceil(3).max(1);
    Some((slots, k))
}

/// One reserve custody leaf: the k-of-n tapscript over the bonded set, in a canonical order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyLeaf {
    /// The x-only key in EACH SLOT, in script order (a weighted member appears once per slot).
    /// O1-FOOTPRINT-REVIEWED: bounded by SLOT_TARGET by construction (`custody_slots` clamps every share to it and adds one slot per member beyond it) — f(the current bonded set), never history
    pub slot_keys: Vec<[u8; 32]>,
    /// How many slot signatures the script demands.
    pub k: u32,
    /// The tapscript bytes: 34 per slot plus the quorum push.
    /// O1-FOOTPRINT-REVIEWED: bounded by SLOT_TARGET by construction (34 bytes per slot of `slot_keys` plus a ≤6-byte quorum push) — f(the current bonded set), never history
    pub script: Vec<u8>,
    /// `TapLeaf` hash of `LEAF_VERSION ‖ compact(len) ‖ script` — also the tree's Merkle root (single leaf).
    pub leaf_hash: [u8; 32],
}

/// Build the custody leaf for `members` = `(x-only key, weight)`. Order-independent: members are sorted by
/// key bytes, so every node derives byte-identical script and address from the same set.
#[must_use]
pub fn custody_leaf(members: &[([u8; 32], u128)]) -> Option<CustodyLeaf> {
    let mut sorted: Vec<([u8; 32], u128)> = members.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted.dedup_by(|a, b| a.0 == b.0);
    let weights: Vec<u128> = sorted.iter().map(|m| m.1).collect();
    let (slots, k) = custody_slots(&weights)?;
    let mut slot_keys: Vec<[u8; 32]> = Vec::new();
    for (m, s) in sorted.iter().zip(slots.iter()) {
        for _ in 0..*s {
            slot_keys.push(m.0);
        }
    }
    custody_leaf_with_slots(&slot_keys, k)
}

/// The general builder: one key per slot (already ordered) and the quorum `k`. Used directly by the regtest
/// oracle test so a unit-slot leaf can be cross-checked against Bitcoin Core's `multi_a` descriptor.
#[must_use]
pub fn custody_leaf_with_slots(slot_keys: &[[u8; 32]], k: u32) -> Option<CustodyLeaf> {
    if slot_keys.is_empty() || k == 0 || k as usize > slot_keys.len() {
        return None;
    }
    for key in slot_keys {
        lift_x(key)?; // a slot key that is not on the curve can never sign — refuse the whole leaf
    }
    let mut script: Vec<u8> = Vec::with_capacity(slot_keys.len() * 34 + 4);
    for (i, key) in slot_keys.iter().enumerate() {
        script.push(0x20);
        script.extend_from_slice(key);
        script.push(if i == 0 { OP_CHECKSIG } else { OP_CHECKSIGADD });
    }
    push_scriptnum(k, &mut script);
    script.push(OP_NUMEQUAL);
    let leaf_hash = leaf_hash_of(&script);
    Some(CustodyLeaf { slot_keys: slot_keys.to_vec(), k, script, leaf_hash })
}

/// `TapLeaf(LEAF_VERSION ‖ compact(len) ‖ script)`.
pub fn leaf_hash_of(script: &[u8]) -> [u8; 32] {
    let mut m = Vec::with_capacity(script.len() + 4);
    m.push(LEAF_VERSION);
    compact_size(script.len() as u64, &mut m);
    m.extend_from_slice(script);
    tagged_hash(b"TapLeaf", &m)
}

/// The taproot output for one reserve deposit: a provably-unspendable internal key (NUMS + a public tweak
/// bound to the swap nonce and the leaf) committing to the custody leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveOutput {
    /// The x-only INTERNAL key the control block reveals at spend time.
    pub internal_x: [u8; 32],
    /// The x-only OUTPUT key — the 32-byte witness program in `scriptPubKey = OP_1 <32>` and the address.
    pub output_x: [u8; 32],
    /// Whether the output point's y is odd — the parity bit in the control block's first byte.
    pub output_parity_odd: bool,
}

/// Derive the reserve output for `leaf` under `swap_nonce`. Every node with the same set and nonce derives
/// the same address; a different nonce gives an unlinkable fresh one. `None` only if a hash landed off-curve
/// (probability ~2⁻¹²⁸ — the caller refuses rather than fabricates).
#[must_use]
pub fn reserve_output(leaf: &CustodyLeaf, swap_nonce: &[u8]) -> Option<ReserveOutput> {
    let nums = lift_x(&NUMS_X)?;
    let mut pre = Vec::with_capacity(32 + swap_nonce.len());
    pre.extend_from_slice(swap_nonce);
    pre.extend_from_slice(&leaf.leaf_hash);
    let t = scalar_of(&tagged_hash(b"USDMD/reserve-internal-v2", &pre));
    let internal = nums + ProjectivePoint::GENERATOR * t; // CLASSICAL-CRYPTO-EXEMPT: NUMS + public tweak — a key-path spender cannot exist (bridge endpoint)
    let (internal_x, _) = x_and_parity(&internal);
    let internal_even = lift_x(&internal_x)?; // BIP 341: the internal key is x-only, implicitly even-y
    let mut tw = Vec::with_capacity(64);
    tw.extend_from_slice(&internal_x);
    tw.extend_from_slice(&leaf.leaf_hash);
    let tweak = scalar_of(&tagged_hash(b"TapTweak", &tw));
    let output = internal_even + ProjectivePoint::GENERATOR * tweak; // CLASSICAL-CRYPTO-EXEMPT: BIP-341 taptweak (bridge endpoint)
    let (output_x, output_parity_odd) = x_and_parity(&output);
    Some(ReserveOutput { internal_x, output_x, output_parity_odd })
}

/// `OP_1 <32-byte program>` — the pay-to-taproot scriptPubKey.
/// BIP 341's taptweak for a single-leaf tree, as a VERIFIER computes it from a control block: the x-only internal key
/// (`control[1..33]`) tweaked by `TapTweak(internal_x ‖ leaf_hash)` gives the output key and its parity — the two things
/// a script-path spend's control block claims about the output it spends. `reserve_output` derives the same tweak when
/// BUILDING; this is the reading side a judge of a raw transaction needs (`btc_sim` plays Bitcoin Core here).
/// §BR-6 (2026-10-28) — THE WALLET'S BUILT-IN BTC VAULT, receive half: a single-key BIP-86 taproot output for a secret the
/// wallet derives from its seed (`H("MUSD/btc-vault/v1" ‖ seed ‖ index)`), one fresh address per cash-out piece. Returns
/// the output x-only key (the address is `reserve_address(hrp, &x)`) and the tweaked secret's parity-adjusted scalar
/// bytes the key-path spend signs with (BIP-341: `t = H_TapTweak(P)`, `Q = P + tG`, the secret negated when `P` has odd
/// y). `None` when the secret reduces to zero (never for a hash-derived secret). CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own
/// curve, spent on Bitcoin — the external bridge endpoint; nothing of the base layer rests on it.
#[must_use]
pub fn vault_single_key_output(secret: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let d = scalar_of(secret); // CLASSICAL-CRYPTO-EXEMPT: the vault key as a secp256k1 scalar (bridge endpoint)
    if bool::from(d.is_zero()) {
        return None;
    }
    let p = ProjectivePoint::GENERATOR * d; // CLASSICAL-CRYPTO-EXEMPT: P = dG on Bitcoin's curve (bridge endpoint)
    let (px, p_odd) = x_and_parity(&p);
    // BIP-340: the x-only key is the even-y point; negate the secret when P has odd y
    let d_even = if p_odd { -d } else { d }; // CLASSICAL-CRYPTO-EXEMPT: scalar negation (bridge endpoint)
    let p_even = lift_x(&px)?;
    let tweak = scalar_of(&tagged_hash(b"TapTweak", &px)); // BIP-86: no script tree, t = H(P)
    let q = p_even + ProjectivePoint::GENERATOR * tweak; // CLASSICAL-CRYPTO-EXEMPT: BIP-341 taptweak (bridge endpoint)
    let (qx, q_odd) = x_and_parity(&q);
    let mut dq = d_even + tweak; // CLASSICAL-CRYPTO-EXEMPT: the tweaked key-path secret (bridge endpoint)
    if q_odd {
        dq = -dq; // CLASSICAL-CRYPTO-EXEMPT: BIP-340 signing key parity (bridge endpoint)
    }
    Some((qx, dq.to_bytes().into()))
}

/// §BR-8 — the BIP-86 key-path output key of an x-only INTERNAL key `px` (`Q = P + H_TapTweak(P)·G`): what a decoy pays to a
/// validator's registered custody point, computed by every custodian from the public point alone. `None` for an x that is
/// not on the curve. CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own curve, on Bitcoin — the external bridge endpoint.
#[must_use]
pub fn bip86_output_from_xonly(px: &[u8; 32]) -> Option<[u8; 32]> {
    let p = lift_x(px)?;
    let tweak = scalar_of(&tagged_hash(b"TapTweak", px));
    let q = p + ProjectivePoint::GENERATOR * tweak; // CLASSICAL-CRYPTO-EXEMPT: BIP-341 taptweak (bridge endpoint)
    Some(x_and_parity(&q).0)
}

// ════════════════════════════ §BR-2 — THE CO-SIGNED DEPOSIT (BIP 341 two-leaf tree) ════════════════════════════
// Spec docs/BRIDGE-USDM-PRIVACY-SPEC §14. A deposit output's tree holds two leaves under a NUMS-tweaked internal key
// (no key path, as the reserve): `sweep` = the depositor AND the custody quorum; `refund` = the depositor alone after
// `DEPOSIT_REFUND_BLOCKS`. BORROWED: BIP 341 script trees, BIP 112 CSV (Bitcoin); pre-signed exits (Lightning).

/// The self-refund's relative lock: one week of Bitcoin blocks (spec §2.1).
pub const DEPOSIT_REFUND_BLOCKS: u32 = 1_008;
/// The mint window: a custodian attests a mint only while its deposit has at most this many confirmations (3 days),
/// leaving the custody ≥ 576 blocks (4 days) to sweep before the refund leaf opens.
pub const DEPOSIT_MINT_WINDOW_CONFS: u64 = 432;
/// `OP_CHECKSIGVERIFY`, `OP_CHECKSEQUENCEVERIFY`, `OP_DROP`.
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
pub const OP_DROP: u8 = 0x75;

/// The sweep leaf: `<D> OP_CHECKSIGVERIFY` then the custody quorum's own `multi_a` script, verbatim.
#[must_use]
pub fn deposit_sweep_leaf(depositor_x: &[u8; 32], custody: &CustodyLeaf) -> Option<Vec<u8>> {
    lift_x(depositor_x)?; // a depositor key off the curve could never sign — the deposit would be custody-proof forever
    let mut s = Vec::with_capacity(34 + custody.script.len());
    s.push(0x20);
    s.extend_from_slice(depositor_x);
    s.push(OP_CHECKSIGVERIFY);
    s.extend_from_slice(&custody.script);
    Some(s)
}

/// The refund leaf: `<1008> OP_CHECKSEQUENCEVERIFY OP_DROP <D> OP_CHECKSIG`.
#[must_use]
pub fn deposit_refund_leaf(depositor_x: &[u8; 32]) -> Option<Vec<u8>> {
    lift_x(depositor_x)?;
    let mut s = Vec::with_capacity(40);
    push_scriptnum(DEPOSIT_REFUND_BLOCKS, &mut s);
    s.push(OP_CHECKSEQUENCEVERIFY);
    s.push(OP_DROP);
    s.push(0x20);
    s.extend_from_slice(depositor_x);
    s.push(OP_CHECKSIG);
    Some(s)
}

/// BIP 341 `TapBranch`: the two child hashes in lexicographic order.
#[must_use]
pub fn tap_branch(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut m = Vec::with_capacity(64);
    m.extend_from_slice(lo);
    m.extend_from_slice(hi);
    tagged_hash(b"TapBranch", &m)
}

/// One co-signed deposit output: its keys, both leaves and the tree's root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositOutput {
    pub internal_x: [u8; 32],
    pub output_x: [u8; 32],
    pub output_parity_odd: bool,
    pub sweep_leaf: Vec<u8>,
    pub refund_leaf: Vec<u8>,
    pub sweep_hash: [u8; 32],
    pub refund_hash: [u8; 32],
    pub merkle_root: [u8; 32],
}

/// The co-signed deposit output for one swap: (custody quorum, swap nonce, depositor key) → the two-leaf taproot output.
#[must_use]
pub fn deposit_output(custody: &CustodyLeaf, depositor_x: &[u8; 32], swap_nonce: &[u8]) -> Option<DepositOutput> {
    let sweep_leaf = deposit_sweep_leaf(depositor_x, custody)?;
    let refund_leaf = deposit_refund_leaf(depositor_x)?;
    let sweep_hash = leaf_hash_of(&sweep_leaf);
    let refund_hash = leaf_hash_of(&refund_leaf);
    let merkle_root = tap_branch(&sweep_hash, &refund_hash);
    let nums = lift_x(&NUMS_X)?;
    let mut pre = Vec::with_capacity(32 + swap_nonce.len());
    pre.extend_from_slice(swap_nonce);
    pre.extend_from_slice(&merkle_root);
    let t = scalar_of(&tagged_hash(b"USDMD/deposit-internal-v1", &pre));
    let internal = nums + ProjectivePoint::GENERATOR * t; // CLASSICAL-CRYPTO-EXEMPT: NUMS + public tweak — no key-path spender (bridge endpoint)
    let (internal_x, _) = x_and_parity(&internal);
    let (output_x, output_parity_odd) = taproot_output_for_leaf(&internal_x, &merkle_root)?;
    Some(DepositOutput { internal_x, output_x, output_parity_odd, sweep_leaf, refund_leaf, sweep_hash, refund_hash, merkle_root })
}

/// The most a deposit's sweep may pay in fee: 0.001 BTC, and never more than a tenth of the deposit — a sweep is one
/// input and one output (~200 vB), so this admits ≥ 500 sat/vB, past every fee spike Bitcoin has seen, while a wallet
/// (or a forged authorization) can never hand most of a deposit to miners.
pub const DEPOSIT_SWEEP_FEE_MAX_SATS: u64 = 100_000;
/// The least a sweep may pay: 5 sat/vB on its ~200 vB, so it relays (Core's 1 sat/vB floor, with headroom). A sweep that
/// a fee spike leaves unconfirmed is bumped by the custody alone — its output is a custody-only reserve coin, so a
/// child-pays-for-parent spend needs no depositor (Bitcoin Core CPFP).
pub const DEPOSIT_SWEEP_FEE_MIN_SATS: u64 = 1_000;

/// The nonce the sweep's output reserve address is tweaked under: a function of the deposit's own nonce, so every
/// custodian derives the same sweep output from the sealed leg alone.
#[must_use]
/// ⭐ SAFE AT SCALE, stage three (spec §3f R3) — THE NONCE OF A CUSTODY KEY'S HOME ADDRESS: the one address under a
/// vault key's leaf that every node derives from the chain's key record alone (the key's leaf: a member set and its
/// weights, which no two vaults share). A consolidation pays there, and so does a payout's change once a key is
/// recorded, so a custodian that joined yesterday, restarted, or missed every gossip message finds its vault's coins
/// from its own chain and its own Bitcoin source. The address is reused by design: every coin there was linked to
/// the reserve on Bitcoin the moment the script path that spent its inputs revealed the custody leaf, so the reuse
/// tells an observer nothing new.
pub fn home_nonce(leaf_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/btc-custody/home-nonce/v1");
    h.update(leaf_hash);
    *h.finalize().as_bytes()
}

pub fn sweep_nonce(deposit_nonce: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/btc-deposit/sweep-nonce/v1");
    h.update(deposit_nonce);
    *h.finalize().as_bytes()
}

/// ⭐ §BR-2 — THE SWEEP TRANSACTION, one spelling for the wallet that signs it and every custodian that completes it:
/// the deposit coin (`txid:vout`, `value_sats`, the deposit output's script) → ONE output paying `value_sats − fee_sats`
/// to the custody's single-leaf reserve address under [`sweep_nonce`] — the reserve coin the payout lane spends later.
/// `None` when the fee is out of bounds or the output would be dust.
#[must_use]
pub fn deposit_sweep_payout(
    out: &DepositOutput,
    custody: &CustodyLeaf,
    deposit_nonce: &[u8],
    txid: [u8; 32],
    vout: u32,
    value_sats: u64,
    fee_sats: u64,
) -> Option<(Payout, ReserveOutput)> {
    if fee_sats < DEPOSIT_SWEEP_FEE_MIN_SATS || fee_sats > DEPOSIT_SWEEP_FEE_MAX_SATS || fee_sats > value_sats / 10 {
        return None;
    }
    let keep = value_sats.checked_sub(fee_sats)?;
    if keep < DUST_SATS {
        return None;
    }
    let sweep_out = reserve_output(custody, &sweep_nonce(deposit_nonce))?;
    let payout = Payout {
        inputs: vec![TxIn { txid, vout, value_sats, script_pubkey: p2tr_script_pubkey(&out.output_x), sequence: 0xffff_fffd }],
        outputs: vec![TxOut { value_sats: keep, script_pubkey: p2tr_script_pubkey(&sweep_out.output_x) }],
    };
    Some((payout, sweep_out))
}

/// The sighash the depositor signs (and the custody quorum signs) for the sweep: BIP 341 script path over the sweep leaf.
#[must_use]
pub fn deposit_sweep_sighash(payout: &Payout, out: &DepositOutput) -> Option<[u8; 32]> {
    payout.sighash_script_path(0, &out.sweep_hash)
}

/// ⭐ §BR-2 — does `sig` authorize the sweep of this deposit coin? The custodian's attest door asks this before it signs a
/// mint: the transaction is rebuilt from the sealed fields alone and the depositor's BIP-340 signature must verify over
/// its sweep-leaf sighash. A wrong key, coin, value, fee, output or signature answers `false`.
#[must_use]
pub fn sweep_authorization_verifies(
    custody: &CustodyLeaf,
    depositor_x: &[u8; 32],
    deposit_nonce: &[u8],
    txid: [u8; 32],
    vout: u32,
    value_sats: u64,
    fee_sats: u64,
    sig: &[u8; 64],
) -> bool {
    let Some(out) = deposit_output(custody, depositor_x, deposit_nonce) else { return false };
    let Some((payout, _)) = deposit_sweep_payout(&out, custody, deposit_nonce, txid, vout, value_sats, fee_sats) else {
        return false;
    };
    let Some(m) = deposit_sweep_sighash(&payout, &out) else { return false };
    verify_sighash_sig(depositor_x, &m, sig) // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own BIP-340 verify of the depositor's foreign-chain signature (bridge endpoint)
}

/// The control block spending one leaf of a deposit: `(c0 | parity) ‖ internal_x ‖ sibling` (65 bytes, BIP 341).
#[must_use]
pub fn deposit_control_block(out: &DepositOutput, sweep: bool) -> Vec<u8> {
    let mut c = Vec::with_capacity(65);
    c.push(LEAF_VERSION | u8::from(out.output_parity_odd));
    c.extend_from_slice(&out.internal_x);
    c.extend_from_slice(if sweep { &out.refund_hash } else { &out.sweep_hash });
    c
}

pub fn taproot_output_for_leaf(internal_x: &[u8; 32], leaf_hash: &[u8; 32]) -> Option<([u8; 32], bool)> {
    let internal_even = lift_x(internal_x)?;
    let mut tw = Vec::with_capacity(64);
    tw.extend_from_slice(internal_x);
    tw.extend_from_slice(leaf_hash);
    let tweak = scalar_of(&tagged_hash(b"TapTweak", &tw));
    let output = internal_even + ProjectivePoint::GENERATOR * tweak; // CLASSICAL-CRYPTO-EXEMPT: BIP-341 taptweak, verifier side (bridge endpoint)
    Some(x_and_parity(&output))
}

pub fn p2tr_script_pubkey(output_x: &[u8; 32]) -> Vec<u8> {
    let mut s = Vec::with_capacity(34);
    s.push(OP_1);
    s.push(0x20);
    s.extend_from_slice(output_x);
    s
}

/// The bech32m address of a reserve output for `hrp` (`bc`, `tb` or `bcrt`).
pub fn reserve_address(hrp: &str, output_x: &[u8; 32]) -> String {
    crate::bridge::encode_segwit(hrp, 1, output_x)
}

/// The control block for a single-leaf script-path spend: `(LEAF_VERSION | parity) ‖ internal_x`.
pub fn control_block(out: &ReserveOutput) -> Vec<u8> {
    let mut c = Vec::with_capacity(33);
    c.push(LEAF_VERSION | u8::from(out.output_parity_odd));
    c.extend_from_slice(&out.internal_x);
    c
}

/// One input a payout spends — a reserve coin, with what BIP 341 needs to sign it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    /// The funding txid in INTERNAL byte order (as hashed, not as displayed).
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sats: u64,
    /// The coin's scriptPubKey (the reserve output's `OP_1 <32>`), part of the signed message.
    /// O1-FOOTPRINT-REVIEWED: bounded by SCRIPT_PUBKEY_MAX by construction (a taproot coin's scriptPubKey is exactly 34 bytes)
    pub script_pubkey: Vec<u8>,
    pub sequence: u32,
}

/// One output a payout pays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value_sats: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by SCRIPT_PUBKEY_MAX by construction (`script_pubkey_for_address` emits only the five standard shapes, the widest 34 bytes)
    pub script_pubkey: Vec<u8>,
}

/// An unsigned payout transaction: version 2, lock time 0, every input a reserve coin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    /// O1-FOOTPRINT-REVIEWED: bounded by PAYOUT_INPUTS_MAX by construction (the lane never assembles more coins than it into one transaction)
    pub inputs: Vec<TxIn>,
    /// O1-FOOTPRINT-REVIEWED: bounded by BATCH_MAX by construction (crate::peg_pool::BATCH_MAX legs plus one change output)
    pub outputs: Vec<TxOut>,
}

pub const TX_VERSION: i32 = 2;
pub const LOCK_TIME: u32 = 0;
/// SIGHASH_DEFAULT — all inputs, all outputs; the signature carries no hash-type byte.
pub const SIGHASH_DEFAULT: u8 = 0x00;

impl Payout {
    fn write_inputs_no_witness(&self, out: &mut Vec<u8>) {
        compact_size(self.inputs.len() as u64, out);
        for i in &self.inputs {
            out.extend_from_slice(&i.txid);
            out.extend_from_slice(&i.vout.to_le_bytes());
            out.push(0x00); // empty scriptSig — taproot spends carry everything in the witness
            out.extend_from_slice(&i.sequence.to_le_bytes());
        }
    }

    fn write_outputs(&self, out: &mut Vec<u8>) {
        compact_size(self.outputs.len() as u64, out);
        for o in &self.outputs {
            out.extend_from_slice(&o.value_sats.to_le_bytes());
            compact_size(o.script_pubkey.len() as u64, out);
            out.extend_from_slice(&o.script_pubkey);
        }
    }

    /// Legacy serialization (no witness) — what `txid` hashes.
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&TX_VERSION.to_le_bytes());
        self.write_inputs_no_witness(&mut b);
        self.write_outputs(&mut b);
        b.extend_from_slice(&LOCK_TIME.to_le_bytes());
        b
    }

    /// BIP 144 serialization with one witness stack per input.
    pub fn serialize_with_witness(&self, witnesses: &[Vec<Vec<u8>>]) -> Option<Vec<u8>> {
        if witnesses.len() != self.inputs.len() {
            return None;
        }
        let mut b = Vec::new();
        b.extend_from_slice(&TX_VERSION.to_le_bytes());
        b.push(0x00);
        b.push(0x01);
        self.write_inputs_no_witness(&mut b);
        self.write_outputs(&mut b);
        for w in witnesses {
            compact_size(w.len() as u64, &mut b);
            for item in w {
                compact_size(item.len() as u64, &mut b);
                b.extend_from_slice(item);
            }
        }
        b.extend_from_slice(&LOCK_TIME.to_le_bytes());
        Some(b)
    }

    /// The txid in INTERNAL byte order.
    pub fn txid(&self) -> [u8; 32] {
        sha256d(&self.serialize_legacy())
    }

    /// BIP 341 script-path sighash (SIGHASH_DEFAULT) for `input_index` under `leaf_hash`. Every custodian
    /// computes this from the same proposal bytes, so their independent signatures land on one message.
    pub fn sighash_script_path(&self, input_index: usize, leaf_hash: &[u8; 32]) -> Option<[u8; 32]> {
        self.sighash_bip341(input_index, Some(leaf_hash))
    }

    /// §BR-6 — BIP 341 KEY-PATH sighash (SIGHASH_DEFAULT) for `input_index`: the message a single-key taproot coin (the
    /// wallet's BTC vault, BIP 86) signs to spend itself — the same message as the script path with `ext_flag = 0` and no
    /// leaf extension (BIP 341 "Common signature message", `spend_type = 0x00`).
    pub fn sighash_key_path(&self, input_index: usize) -> Option<[u8; 32]> {
        self.sighash_bip341(input_index, None)
    }

    fn sighash_bip341(&self, input_index: usize, leaf_hash: Option<&[u8; 32]>) -> Option<[u8; 32]> {
        if input_index >= self.inputs.len() {
            return None;
        }
        let mut prevouts = Sha256::new();
        let mut amounts = Sha256::new();
        let mut spks = Sha256::new();
        let mut seqs = Sha256::new();
        for i in &self.inputs {
            prevouts.update(i.txid);
            prevouts.update(i.vout.to_le_bytes());
            amounts.update(i.value_sats.to_le_bytes());
            let mut l = Vec::with_capacity(9);
            compact_size(i.script_pubkey.len() as u64, &mut l);
            spks.update(&l);
            spks.update(&i.script_pubkey);
            seqs.update(i.sequence.to_le_bytes());
        }
        let mut outs = Sha256::new();
        for o in &self.outputs {
            outs.update(o.value_sats.to_le_bytes());
            let mut l = Vec::with_capacity(9);
            compact_size(o.script_pubkey.len() as u64, &mut l);
            outs.update(&l);
            outs.update(&o.script_pubkey);
        }
        let mut m = Vec::with_capacity(1 + 1 + 4 + 4 + 32 * 5 + 1 + 4 + 32 + 1 + 4);
        m.push(0x00); // epoch
        m.push(SIGHASH_DEFAULT);
        m.extend_from_slice(&TX_VERSION.to_le_bytes());
        m.extend_from_slice(&LOCK_TIME.to_le_bytes());
        m.extend_from_slice(&prevouts.finalize());
        m.extend_from_slice(&amounts.finalize());
        m.extend_from_slice(&spks.finalize());
        m.extend_from_slice(&seqs.finalize());
        m.extend_from_slice(&outs.finalize());
        match leaf_hash {
            Some(leaf_hash) => {
                m.push(0x02); // spend_type: ext_flag = 1 (script path), no annex
                m.extend_from_slice(&(input_index as u32).to_le_bytes());
                m.extend_from_slice(leaf_hash);
                m.push(0x00); // key_version
                m.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // codeseparator position: none
            }
            None => {
                m.push(0x00); // spend_type: ext_flag = 0 (key path), no annex
                m.extend_from_slice(&(input_index as u32).to_le_bytes());
            }
        }
        Some(tagged_hash(b"TapSighash", &m))
    }

    /// Virtual size of the fully-signed transaction, for the fee: every input carries exactly `k` signatures
    /// plus empty pushes for the other slots, the leaf script and a 33-byte control block.
    pub fn estimate_vbytes(&self, leaf: &CustodyLeaf) -> u64 {
        let base: u64 = 4 + 1 + self.inputs.len() as u64 * 41 + 1
            + self.outputs.iter().map(|o| 8 + 1 + o.script_pubkey.len() as u64).sum::<u64>()
            + 4;
        let slots = leaf.slot_keys.len() as u64;
        let mut script_len = Vec::with_capacity(9);
        compact_size(leaf.script.len() as u64, &mut script_len);
        let per_input_witness: u64 =
            1 + leaf.k as u64 * 65 + (slots - leaf.k as u64) + script_len.len() as u64 + leaf.script.len() as u64 + 34;
        let weight = base * 4 + 2 + per_input_witness * self.inputs.len() as u64;
        weight.div_ceil(4)
    }
}

/// The x-only public key of a custodian's secp256k1 secret — what its slot in the leaf holds.
/// TEST-ONLY (dev builds and the `bridge-test-oracle` feature — compiled out of a release daemon): a REAL taproot
/// address whose key this test derives from `seed`, on network `hrp`. Fixtures name destinations and reserves
/// with this instead of made-up strings (owner 2026-09-21: "there should be no placeholder addresses left, which
/// is a funds loss bug; only real derived reserve addresses") — a string a Bitcoin node cannot pay is exactly the
/// shape a production path must never be handed, so no test hands one to the code under test either.
#[cfg(any(test, feature = "bridge-test-oracle"))]
pub fn address_for_test_seed(hrp: &str, seed: &[u8]) -> String {
    let secret: [u8; 32] = *blake3::hash(seed).as_bytes();
    // a hash is a valid secp256k1 secret with overwhelming probability; the (unreachable) exceptions re-hash until one is
    let mut secret = secret;
    let x = loop {
        if let Some(x) = xonly_pubkey(&secret) {
            break x;
        }
        secret = *blake3::hash(&secret).as_bytes();
    };
    reserve_address(hrp, &x)
}

pub fn xonly_pubkey(secret: &[u8; 32]) -> Option<[u8; 32]> {
    let sk = k256::schnorr::SigningKey::from_bytes(secret).ok()?; // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's BIP-340 key at the bridge endpoint
    let b = sk.verifying_key().to_bytes();
    <[u8; 32]>::try_from(b.as_slice()).ok()
}

/// A custodian's BIP-340 signature over a sighash. `aux_rand` is fresh randomness per signature (BIP 340's
/// auxiliary input; a fixed value is still secure but a fresh one hardens against fault attacks).
pub fn sign_sighash(secret: &[u8; 32], sighash: &[u8; 32], aux_rand: &[u8; 32]) -> Option<[u8; 64]> {
    let sk = k256::schnorr::SigningKey::from_bytes(secret).ok()?; // CLASSICAL-CRYPTO-EXEMPT: the reserve custody signer — a taproot coin is spendable by BIP-340 and nothing else (bridge endpoint)
    let sig = sk.sign_prehash_with_aux_rand(sighash, aux_rand).ok()?; // CLASSICAL-CRYPTO-EXEMPT: BIP-340 signing (bridge endpoint)
    let b = sig.to_bytes();
    <[u8; 64]>::try_from(b.as_slice()).ok()
}

/// Verify one slot signature against the slot's x-only key and the sighash — what a gatherer checks before it
/// counts a peer's signature, and what Bitcoin's `OP_CHECKSIGADD` will check again.
pub fn verify_sighash_sig(xonly: &[u8; 32], sighash: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Ok(vk) = k256::schnorr::VerifyingKey::from_bytes(xonly) else { // CLASSICAL-CRYPTO-EXEMPT: BIP-340 verify of a foreign-chain signature (bridge endpoint)
        return false;
    };
    let Ok(s) = k256::schnorr::Signature::try_from(&sig[..]) else { // CLASSICAL-CRYPTO-EXEMPT: BIP-340 signature parse (bridge endpoint)
        return false;
    };
    vk.verify_raw(sighash, &s).is_ok()
}

/// Assemble one input's witness from per-slot signatures: exactly `k` signatures are kept (the first `k`
/// slots that have one, in script order), every other slot gets an empty push, then the script and the
/// control block. `None` when fewer than `k` slots are signed — a short witness is never broadcast.
///
/// Stack order: the script's first `<pk_0> OP_CHECKSIG` pops the TOP of the initial stack, and the witness
/// lists items bottom-first, so slot 0's item is the LAST signature item.
pub fn script_path_witness(
    leaf: &CustodyLeaf,
    slot_sigs: &[Option<[u8; 64]>],
    control: &[u8],
) -> Option<Vec<Vec<u8>>> {
    if slot_sigs.len() != leaf.slot_keys.len() {
        return None;
    }
    let mut kept = 0u32;
    let mut items_top_first: Vec<Vec<u8>> = Vec::with_capacity(slot_sigs.len() + 2);
    for s in slot_sigs {
        match s {
            Some(sig) if kept < leaf.k => {
                kept += 1;
                items_top_first.push(sig.to_vec());
            }
            _ => items_top_first.push(Vec::new()),
        }
    }
    if kept < leaf.k {
        return None;
    }
    items_top_first.reverse();
    items_top_first.push(leaf.script.clone());
    items_top_first.push(control.to_vec());
    Some(items_top_first)
}

/// The Bitcoin network an address belongs to — a payout refuses a destination on another network than its
/// reserve (a mainnet coin can never be "paid" to a testnet address, and the wallet's own check may be stale).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcNet {
    Mainnet,
    Testnet,
    Regtest,
}

impl BtcNet {
    pub fn hrp(self) -> &'static str {
        match self {
            BtcNet::Mainnet => "bc",
            BtcNet::Testnet => "tb",
            BtcNet::Regtest => "bcrt",
        }
    }
}

/// Decode any standard Bitcoin address into `(network, scriptPubKey)`: bech32 v0 (P2WPKH/P2WSH), bech32m v1
/// (P2TR) and base58check legacy (P2PKH/P2SH). Anything else is `None` — a redeemer's coins are never sent to
/// a string this node cannot fully account for.
pub fn script_pubkey_for_address(addr: &str) -> Option<(BtcNet, Vec<u8>)> {
    let a = addr.trim();
    if let Some(r) = decode_segwit(a) {
        return Some(r);
    }
    decode_base58check(a)
}

fn decode_segwit(a: &str) -> Option<(BtcNet, Vec<u8>)> {
    let lower = a.to_ascii_lowercase();
    if lower != a && a.to_ascii_uppercase() != a {
        return None; // mixed case is invalid bech32
    }
    let pos = lower.rfind('1')?;
    let (hrp, data_part) = (&lower[..pos], &lower[pos + 1..]);
    if data_part.len() < 7 {
        return None;
    }
    let net = match hrp {
        "bc" => BtcNet::Mainnet,
        "tb" => BtcNet::Testnet,
        "bcrt" => BtcNet::Regtest,
        _ => return None,
    };
    let mut values: Vec<u8> = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        values.push(crate::bridge::CHARSET.iter().position(|x| *x == c)? as u8);
    }
    let mut poly_in = crate::bridge::hrp_expand(hrp);
    poly_in.extend_from_slice(&values);
    let check = crate::bridge::bech32_polymod(&poly_in);
    let witver = values[0];
    let program = crate::bridge::convertbits(&values[1..values.len() - 6], 5, 8, false)?;
    match (witver, check, program.len()) {
        (0, c, 20) | (0, c, 32) if c == crate::bridge::BECH32_CONST => {
            let mut s = Vec::with_capacity(2 + program.len());
            s.push(0x00);
            s.push(program.len() as u8);
            s.extend_from_slice(&program);
            Some((net, s))
        }
        (1, c, 32) if c == crate::bridge::BECH32M_CONST => {
            let mut x = [0u8; 32];
            x.copy_from_slice(&program);
            Some((net, p2tr_script_pubkey(&x)))
        }
        _ => None,
    }
}

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn decode_base58check(a: &str) -> Option<(BtcNet, Vec<u8>)> {
    let mut big: Vec<u8> = vec![0];
    for c in a.bytes() {
        let mut carry = B58.iter().position(|x| *x == c)? as u32;
        for b in big.iter_mut().rev() {
            let v = *b as u32 * 58 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            big.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let leading = a.bytes().take_while(|c| *c == b'1').count();
    let mut bytes: Vec<u8> = vec![0; leading];
    let first_nonzero = match big.iter().position(|b| *b != 0) {
        Some(i) => i,
        None => big.len(), // every limb zero: the number is exactly the leading-one count
    };
    bytes.extend_from_slice(&big[first_nonzero..]);
    if bytes.len() != 25 {
        return None;
    }
    let (payload, checksum) = bytes.split_at(21);
    if sha256d(payload)[..4] != checksum[..] {
        return None;
    }
    let hash160 = &payload[1..21];
    let p2pkh = |h: &[u8]| {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(h);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    };
    let p2sh = |h: &[u8]| {
        let mut s = vec![0xa9, 0x14];
        s.extend_from_slice(h);
        s.push(0x87);
        s
    };
    match payload[0] {
        0x00 => Some((BtcNet::Mainnet, p2pkh(hash160))),
        0x05 => Some((BtcNet::Mainnet, p2sh(hash160))),
        0x6f => Some((BtcNet::Testnet, p2pkh(hash160))),
        0xc4 => Some((BtcNet::Testnet, p2sh(hash160))),
        _ => None,
    }
}

/// A txid as explorers and Bitcoin Core display it (byte-reversed hex) → internal order.
pub fn txid_from_display_hex(hex: &str) -> Option<[u8; 32]> {
    let raw = unhex(hex.trim())?;
    if raw.len() != 32 {
        return None;
    }
    let mut t = [0u8; 32];
    for (i, b) in raw.iter().rev().enumerate() {
        t[i] = *b;
    }
    Some(t)
}

/// Internal-order txid → the display form.
pub fn txid_display_hex(txid: &[u8; 32]) -> String {
    txid.iter().rev().map(|b| format!("{b:02x}")).collect()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn h32(s: &str) -> [u8; 32] {
        let v = unhex(s).expect("hex");
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    /// BIP 341 wallet-test-vectors.json, key-path case: the taptweak of a bare internal key and its address.
    #[test]
    fn bip341_key_path_vector_taptweak_and_address() {
        let internal = h32("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
        let tweak = tagged_hash(b"TapTweak", &internal);
        assert_eq!(hex(&tweak), "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70");
        let p = lift_x(&internal).expect("on curve");
        let q = p + ProjectivePoint::GENERATOR * scalar_of(&tweak); // CLASSICAL-CRYPTO-EXEMPT: BIP-341 published vector check (bridge endpoint test)
        let (qx, _) = x_and_parity(&q);
        assert_eq!(hex(&qx), "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343");
        assert_eq!(hex(&p2tr_script_pubkey(&qx)), "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343");
        assert_eq!(reserve_address("bc", &qx), "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5");
    }

    /// BIP 341 wallet-test-vectors.json, single-leaf case: leaf hash, tweak with the Merkle root, output key.
    #[test]
    fn bip341_single_leaf_vector_leaf_hash_tweak_output_and_address() {
        let script = unhex("20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac").expect("hex");
        let lh = leaf_hash_of(&script);
        assert_eq!(hex(&lh), "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21");
        let internal = h32("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27");
        let mut tw = internal.to_vec();
        tw.extend_from_slice(&lh);
        let tweak = tagged_hash(b"TapTweak", &tw);
        assert_eq!(hex(&tweak), "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001");
        let q = lift_x(&internal).expect("on curve") + ProjectivePoint::GENERATOR * scalar_of(&tweak); // CLASSICAL-CRYPTO-EXEMPT: BIP-341 published vector check (bridge endpoint test)
        let (qx, _) = x_and_parity(&q);
        assert_eq!(hex(&qx), "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3");
        assert_eq!(reserve_address("bc", &qx), "bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586");
    }

    /// The slot split reproduces the tally's ≥2/3-of-weight quorum: with n equal members exactly ⌈2n/3⌉ of
    /// them reach k, and a 3:1 holder alone reaches it exactly as `attested·3 ≥ total·2` says it does.
    #[test]
    fn custody_slots_match_the_bond_weighted_tally() {
        for n in 1..=9usize {
            let (slots, k) = custody_slots(&vec![1u128; n]).expect("slots");
            let per = slots[0];
            assert!(slots.iter().all(|s| *s == per), "equal weights → equal slots");
            let need = (0..=n).find(|m| (*m as u32) * per >= k).expect("some count reaches k");
            assert_eq!(need, (2 * n).div_ceil(3), "n={n}: {need} members reach k={k} with {per} slots each");
        }
        let (slots, k) = custody_slots(&[3, 1]).expect("slots");
        assert_eq!(slots, vec![45, 15]);
        assert!(slots[0] >= k && slots[1] < k, "the 3/4 holder alone passes, the 1/4 holder alone does not");
        assert!(custody_slots(&[]).is_none());
    }

    fn secret(i: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = i;
        s[0] = 0x11;
        s
    }

    #[test]
    fn the_leaf_is_order_independent_and_its_witness_puts_slot_zero_on_top() {
        let keys: Vec<[u8; 32]> = (1..=3u8).map(|i| xonly_pubkey(&secret(i)).expect("key")).collect();
        let a = custody_leaf(&[(keys[0], 1), (keys[1], 1), (keys[2], 1)]).expect("leaf");
        let b = custody_leaf(&[(keys[2], 1), (keys[0], 1), (keys[1], 1)]).expect("leaf");
        assert_eq!(a, b, "the same set in any order derives one script");
        assert_eq!(a.slot_keys.len(), 60);
        assert_eq!(a.k, 40);
        // a unit-slot leaf shows the stack order plainly
        let unit = custody_leaf_with_slots(&keys, 2).expect("leaf");
        let sig0 = [1u8; 64];
        let sig2 = [3u8; 64];
        let w = script_path_witness(&unit, &[Some(sig0), None, Some(sig2)], &[0xc0; 33]).expect("k reached");
        assert_eq!(w.len(), 5);
        assert_eq!(w[0], sig2.to_vec(), "slot 2 is deepest");
        assert!(w[1].is_empty(), "slot 1 unsigned → empty push");
        assert_eq!(w[2], sig0.to_vec(), "slot 0 is on top of the signatures");
        assert_eq!(w[3], unit.script);
        assert!(script_path_witness(&unit, &[Some(sig0), None, None], &[0xc0; 33]).is_none(), "one short of k → no witness");
    }

    #[test]
    fn sign_verify_round_trip_and_a_changed_output_changes_the_sighash() {
        let keys: Vec<[u8; 32]> = (1..=2u8).map(|i| xonly_pubkey(&secret(i)).expect("key")).collect();
        let leaf = custody_leaf(&[(keys[0], 1), (keys[1], 1)]).expect("leaf");
        let out = reserve_output(&leaf, b"swap-1").expect("output");
        let other = reserve_output(&leaf, b"swap-2").expect("output");
        assert_ne!(out.output_x, other.output_x, "a fresh nonce is a fresh address");
        let (_, spk) = script_pubkey_for_address(&reserve_address("bcrt", &out.output_x)).expect("our own address decodes");
        assert_eq!(spk, p2tr_script_pubkey(&out.output_x));
        let tx = Payout {
            inputs: vec![TxIn { txid: [7u8; 32], vout: 1, value_sats: 100_000, script_pubkey: spk.clone(), sequence: 0xffff_fffd }],
            outputs: vec![TxOut { value_sats: 99_000, script_pubkey: spk.clone() }],
        };
        let sh = tx.sighash_script_path(0, &leaf.leaf_hash).expect("sighash");
        let sig = sign_sighash(&secret(1), &sh, &[9u8; 32]).expect("sign");
        assert!(verify_sighash_sig(&keys[0], &sh, &sig));
        assert!(!verify_sighash_sig(&keys[1], &sh, &sig), "another slot's key does not verify it");
        let mut tx2 = tx.clone();
        tx2.outputs[0].value_sats -= 1;
        let sh2 = tx2.sighash_script_path(0, &leaf.leaf_hash).expect("sighash");
        assert_ne!(sh, sh2);
        assert!(!verify_sighash_sig(&keys[0], &sh2, &sig), "a signature never travels to a changed payout");
        assert!(
            tx.estimate_vbytes(&leaf) > 600,
            "60 slots and 40 signatures estimate {} vbytes — under the 600 this shape must exceed, so the \
             estimator is no longer describing a fat-but-standard input",
            tx.estimate_vbytes(&leaf)
        );
    }

    #[test]
    fn every_standard_address_kind_decodes_to_its_script_and_garbage_does_not() {
        // BIP 173 / BIP 350 reference vectors
        let (n, s) = script_pubkey_for_address("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").expect("v0 p2wpkh");
        assert_eq!((n, hex(&s).as_str()), (BtcNet::Mainnet, "0014751e76e8199196d454941c45d1b3a323f1433bd6"));
        let (n, s) = script_pubkey_for_address("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7").expect("v0 p2wsh");
        assert_eq!((n, hex(&s).as_str()), (BtcNet::Testnet, "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"));
        let (n, s) = script_pubkey_for_address("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0").expect("v1 p2tr");
        assert_eq!((n, hex(&s).as_str()), (BtcNet::Mainnet, "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));
        let (n, s) = script_pubkey_for_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").expect("p2pkh");
        assert_eq!((n, hex(&s).as_str()), (BtcNet::Mainnet, "76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac"));
        let (n, s) = script_pubkey_for_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").expect("p2sh");
        assert_eq!(n, BtcNet::Mainnet);
        assert_eq!((s[0], s[1], s[22], s.len()), (0xa9, 0x14, 0x87, 23));
        assert!(script_pubkey_for_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5").is_none(), "one bad checksum char");
        assert!(script_pubkey_for_address("tb1pnotanaddress").is_none());
        assert!(script_pubkey_for_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3").is_none(), "bad base58 checksum");
        assert!(script_pubkey_for_address("").is_none());
    }

    #[test]
    fn txid_display_order_round_trips() {
        let d = "e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468";
        let t = txid_from_display_hex(d).expect("txid");
        assert_eq!(txid_display_hex(&t), d);
        assert_eq!(t[0], 0x68);
    }

    // ═════════════════════════════ THE ORACLE — a real Bitcoin Core judges the spend ═════════════════════════════
    //
    // Opt-in (`MONEROUSD_BTC_REGTEST_TEST=1`; Bitcoin Core's binaries in `MONEROUSD_BITCOIN_BIN_DIR`, default
    // /opt/homebrew/bin): starts a throwaway regtest node, cross-checks our unit-slot address against Core's own
    // `multi_a` descriptor, funds the PRODUCTION weighted leaf's address, pays it out with 2 of 3 custodians'
    // independent signatures and asks Core to accept the transaction; then proves 1 of 3 is refused. This is the
    // verdict a hand-written verifier cannot give: Bitcoin's own script interpreter and signature check.
    struct Regtest {
        dir: std::path::PathBuf,
        port: u16,
        bin_dir: String,
    }

    impl Regtest {
        /// `-daemonwait` returns only once the node is initialised and serving RPC (or exits non-zero), so the
        /// readiness verdict is Bitcoin Core's own — no polling budget stands between us and it.
        fn start() -> Regtest {
            let bin_dir = match std::env::var("MONEROUSD_BITCOIN_BIN_DIR") {
                Ok(d) if !d.is_empty() => d,
                _ => "/opt/homebrew/bin".to_string(),
            };
            let block = crate::test_ports::reserve(30000, 2).expect("a free loopback port block for Core");
            let port = block.first;
            let dir = std::env::temp_dir().join(format!("usdmd-btc-regtest-{}-{}", std::process::id(), block.instance));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("regtest dir");
            let st = std::process::Command::new(format!("{bin_dir}/bitcoind"))
                .args(["-regtest", &format!("-datadir={}", dir.display()), &format!("-rpcport={port}"), &format!("-port={}", port + 1),
                       "-listen=0", "-server=1", "-txindex=1", "-rpcuser=u", "-rpcpassword=p", "-daemonwait"])
                .status()
                .expect("bitcoind starts");
            assert!(st.success(), "bitcoind -daemonwait reported a failed start");
            Regtest { dir, port, bin_dir }
        }
        fn cli_with(&self, wallet: bool, args: &[&str]) -> Option<String> {
            let mut c = std::process::Command::new(format!("{}/bitcoin-cli", self.bin_dir));
            c.args(["-regtest", &format!("-datadir={}", self.dir.display()), &format!("-rpcport={}", self.port), "-rpcuser=u", "-rpcpassword=p"]);
            if wallet { c.arg("-rpcwallet=w"); }
            let out = c.args(args).output().ok()?;
            if !out.status.success() { return None; }
            Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        /// A node-level call (no wallet routing).
        fn cli(&self, args: &[&str]) -> Option<String> { self.cli_with(false, args) }
        /// A call routed to the test wallet `w`.
        fn wcli(&self, args: &[&str]) -> Option<String> { self.cli_with(true, args) }
        fn json(&self, wallet: bool, args: &[&str]) -> serde_json::Value {
            let s = self.cli_with(wallet, args).unwrap_or_else(|| panic!("bitcoin-cli {args:?} failed"));
            serde_json::from_str(&s).unwrap_or_else(|e| panic!("bitcoin-cli {args:?} answered non-JSON ({e}): {s}"))
        }
    }

    impl Drop for Regtest {
        fn drop(&mut self) {
            let _ = self.cli(&["stop"]);
            std::thread::sleep(std::time::Duration::from_millis(1500));
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn regtest_oracle_bitcoin_core_accepts_a_two_of_three_custody_payout_and_refuses_one_of_three() {
        if std::env::var("MONEROUSD_BTC_REGTEST_TEST").ok().as_deref() != Some("1") {
            return; // opt-in: needs a local Bitcoin Core
        }
        let rt = Regtest::start();
        rt.cli(&["createwallet", "w"]).expect("wallet");
        let miner = rt.wcli(&["getnewaddress", "", "bech32m"]).expect("miner address");
        rt.cli(&["generatetoaddress", "101", &miner]).expect("mine");

        let secrets: Vec<[u8; 32]> = (1..=3u8).map(secret).collect();
        let keys: Vec<[u8; 32]> = secrets.iter().map(|s| xonly_pubkey(s).expect("key")).collect();
        let mut sorted = keys.clone();
        sorted.sort();

        // (a) CROSS-CHECK the derivation against Bitcoin Core: a unit-slot leaf is exactly Core's `multi_a`.
        let unit = custody_leaf_with_slots(&sorted, 2).expect("leaf");
        let unit_out = reserve_output(&unit, b"oracle-unit").expect("output");
        let desc = format!("tr({},multi_a(2,{},{},{}))", hex(&unit_out.internal_x), hex(&sorted[0]), hex(&sorted[1]), hex(&sorted[2]));
        let info = rt.json(false, &["getdescriptorinfo", &desc]);
        let checksummed = info["descriptor"].as_str().expect("descriptor").to_string();
        let derived = rt.json(false, &["deriveaddresses", &checksummed]);
        let core_addr = derived[0].as_str().expect("address");
        assert_eq!(core_addr, reserve_address("bcrt", &unit_out.output_x), "Bitcoin Core derives the same address from the same leaf and internal key");

        // (b) THE PRODUCTION LEAF (weighted slots, 60 keys, k = 40) receives a deposit and pays out on 2 of 3.
        let leaf = custody_leaf(&[(keys[0], 1), (keys[1], 1), (keys[2], 1)]).expect("leaf");
        let out = reserve_output(&leaf, b"oracle-deposit-1").expect("output");
        let reserve_addr = reserve_address("bcrt", &out.output_x);
        let fund_txid = rt.wcli(&["-named", "sendtoaddress", &format!("address={reserve_addr}"), "amount=1.5", "fee_rate=25"]).expect("fund");
        rt.cli(&["generatetoaddress", "1", &miner]).expect("mine");
        let fund = rt.json(false, &["getrawtransaction", &fund_txid, "true"]);
        let vout = fund["vout"].as_array().expect("vout").iter()
            .position(|o| o["scriptPubKey"]["hex"].as_str() == Some(hex(&p2tr_script_pubkey(&out.output_x)).as_str()))
            .expect("our output is in the funding tx");
        let value_btc = fund["vout"][vout]["value"].as_f64().expect("value");
        let value_sats = (value_btc * 1e8).round() as u64;
        assert_eq!(value_sats, 150_000_000);

        let dest = rt.wcli(&["getnewaddress", "", "bech32"]).expect("dest");
        let (net, dest_spk) = script_pubkey_for_address(&dest).expect("dest decodes");
        assert_eq!(net, BtcNet::Regtest);
        let mut tx = Payout {
            inputs: vec![TxIn { txid: txid_from_display_hex(&fund_txid).expect("txid"), vout: vout as u32, value_sats, script_pubkey: p2tr_script_pubkey(&out.output_x), sequence: 0xffff_fffd }],
            outputs: vec![TxOut { value_sats: 0, script_pubkey: dest_spk }],
        };
        let fee = tx.estimate_vbytes(&leaf) * 2; // 2 sat/vB
        tx.outputs[0].value_sats = value_sats - fee;
        let sh = tx.sighash_script_path(0, &leaf.leaf_hash).expect("sighash");
        let control = control_block(&out);
        // two custodians sign independently (their signature is the same for every slot they hold)
        let sign_slots = |signers: &[usize], sh: &[u8; 32]| -> Vec<Option<[u8; 64]>> {
            leaf.slot_keys.iter().map(|k| {
                signers.iter().find(|i| keys[**i] == *k).map(|i| sign_sighash(&secrets[*i], sh, &[0x42; 32]).expect("sign"))
            }).collect()
        };
        let w2 = script_path_witness(&leaf, &sign_slots(&[0, 2], &sh), &control).expect("2 of 3 reaches k");
        let raw2 = hex(&tx.serialize_with_witness(&[w2]).expect("serialize"));
        let verdict = rt.json(false, &["testmempoolaccept", &format!("[\"{raw2}\"]")]);
        assert_eq!(verdict[0]["allowed"].as_bool(), Some(true), "Bitcoin Core refused the 2-of-3 payout: {verdict}");
        let sent = rt.cli(&["sendrawtransaction", &raw2]).expect("broadcast");
        assert_eq!(sent, txid_display_hex(&tx.txid()), "our txid matches Core's");
        rt.cli(&["generatetoaddress", "1", &miner]).expect("mine");
        let confirmed = rt.json(false, &["getrawtransaction", &sent, "true"]);
        assert_eq!(confirmed["confirmations"].as_u64(), Some(1), "the payout confirmed");

        // (c) ONE custodian is refused — its 20 slots never reach k = 40, so no witness even forms…
        assert!(script_path_witness(&leaf, &sign_slots(&[1], &sh), &control).is_none(), "1 of 3 cannot assemble a witness");
        // …and a hand-forced short witness is refused by Bitcoin itself (a distinct txid so the verdict is the
        // script's, not "already known").
        let mut tx_b = tx.clone();
        tx_b.outputs[0].value_sats -= 1;
        let sh_b = tx_b.sighash_script_path(0, &leaf.leaf_hash).expect("sighash");
        let mut forced_b: Vec<Vec<u8>> = sign_slots(&[1], &sh_b).iter().map(|s| match s { Some(sig) => sig.to_vec(), None => Vec::new() }).collect();
        forced_b.reverse();
        forced_b.push(leaf.script.clone());
        forced_b.push(control.clone());
        let raw_b = hex(&tx_b.serialize_with_witness(&[forced_b]).expect("serialize"));
        let verdict_b = rt.json(false, &["testmempoolaccept", &format!("[\"{raw_b}\"]")]);
        assert_eq!(verdict_b[0]["allowed"].as_bool(), Some(false), "Bitcoin Core must refuse a 1-of-3 spend: {verdict_b}");
    }

    /// ⭐ §BR-2 — THE SWEEP AUTHORIZATION VERIFIES ONLY OVER THE EXACT SWEEP. The depositor signs the sweep of one coin;
    /// a custodian rebuilds the transaction from the sealed fields and verifies. Every one-field change refuses: another
    /// depositor key, coin, output index, value, fee, deposit nonce, or a flipped signature byte; a fee below the floor or
    /// above the cap, and a sweep that would leave dust, build no transaction at all.
    #[test]
    fn br2_the_sweep_authorization_verifies_only_over_the_exact_sweep_the_depositor_signed() {
        let slots: Vec<[u8; 32]> = (1..=3u8).map(|i| xonly_pubkey(&secret(i)).expect("key")).collect(); // CLASSICAL-CRYPTO-EXEMPT: test custodians' Bitcoin keys
        let custody = custody_leaf_with_slots(&slots, 2).expect("a 2-of-3 leaf");
        let d_sk = secret(9);
        let d = xonly_pubkey(&d_sk).expect("key"); // CLASSICAL-CRYPTO-EXEMPT: the test depositor's Bitcoin key
        let nonce = b"br2-sweep-nonce";
        let (txid, vout, value, fee) = ([0x51u8; 32], 1u32, 5_000_000u64, 2_000u64);
        let out = deposit_output(&custody, &d, nonce).expect("deposit output");
        let (tx, _) = deposit_sweep_payout(&out, &custody, nonce, txid, vout, value, fee).expect("the sweep builds");
        let m = deposit_sweep_sighash(&tx, &out).expect("sighash");
        let sig = sign_sighash(&d_sk, &m, &[1u8; 32]).expect("sign"); // CLASSICAL-CRYPTO-EXEMPT: the depositor's BIP-340 signature
        assert!(sweep_authorization_verifies(&custody, &d, nonce, txid, vout, value, fee, &sig), "CALIBRATION: the honest sweep verifies");
        let other = xonly_pubkey(&secret(8)).expect("key"); // CLASSICAL-CRYPTO-EXEMPT: another key
        assert!(!sweep_authorization_verifies(&custody, &other, nonce, txid, vout, value, fee, &sig), "⛔ another depositor key verified");
        assert!(!sweep_authorization_verifies(&custody, &d, nonce, [0x52u8; 32], vout, value, fee, &sig), "⛔ another coin verified");
        assert!(!sweep_authorization_verifies(&custody, &d, nonce, txid, 2, value, fee, &sig), "⛔ another output index verified");
        assert!(!sweep_authorization_verifies(&custody, &d, nonce, txid, vout, value + 1, fee, &sig), "⛔ another value verified");
        assert!(!sweep_authorization_verifies(&custody, &d, nonce, txid, vout, value, fee + 1, &sig), "⛔ another fee verified");
        assert!(!sweep_authorization_verifies(&custody, &d, b"other-nonce", txid, vout, value, fee, &sig), "⛔ another deposit verified");
        let mut flipped = sig;
        flipped[33] ^= 1;
        assert!(!sweep_authorization_verifies(&custody, &d, nonce, txid, vout, value, fee, &flipped), "⛔ a flipped signature verified");
        assert!(deposit_sweep_payout(&out, &custody, nonce, txid, vout, value, DEPOSIT_SWEEP_FEE_MIN_SATS - 1).is_none(), "⛔ a fee under the floor built");
        assert!(deposit_sweep_payout(&out, &custody, nonce, txid, vout, value, DEPOSIT_SWEEP_FEE_MAX_SATS + 1).is_none(), "⛔ a fee over the cap built");
        assert!(deposit_sweep_payout(&out, &custody, nonce, txid, vout, 10_000, 1_500).is_none(), "⛔ a fee over a tenth of the deposit built");
        assert!(deposit_sweep_payout(&out, &custody, nonce, txid, vout, 1_500, 1_000).is_none(), "⛔ a sweep leaving dust built");
    }
}
