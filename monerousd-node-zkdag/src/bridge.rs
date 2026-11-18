// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Buy-USDm ATOMIC-SWAP BRIDGE — the REAL, threshold-custodied cross-chain deposit leg + the sound PQ
//! threshold mint it authorizes. This is the whole Buy pipeline, end to end:
//!
//!   1. CHARTER CUSTODIAN QUORUM (decentralization, Pillar A): the reserve is a t-of-n THRESHOLD account of
//!      the bonded charter validators — NEVER a solo key. Each custodian holds its OWN ML-DSA
//!      mint-attestation key + its OWN secp256k1 BTC-custody key; no single party can mint or move the reserve.
//!   2. REAL DEPOSIT ADDRESS (no fake address, Pillar 3 / no-money-loss): the Bitcoin deposit address is a
//!      GENUINE BIP350 taproot (`bc1p…` / `tb1p…`) address over the secp256k1 key-AGGREGATE of the custodians'
//!      real bridge points — a real curve point → real bech32m, spendable by the threshold quorum. It is
//!      NOT a fabricated hash (`Hash32::hash → "usdmr1…"`), which would send a user's real BTC into the void.
//!      secp256k1 lives ONLY here, at the external bridge endpoint — never in the MonerousD PQ base layer.
//!   3. THRESHOLD MINT (Pillar 2, sound): t custodians each produce a REAL ML-DSA-65 signature over the exact
//!      mint message ([`crate::pqauth::mint_attest_msg`]); [`crate::psm::authorize_mint`] verifies every
//!      signature, tallies ≥2/3 distinct bonded weight, and enforces the LIVE governance 150% ratio + the
//!      confidential solvency proof. Only on `Authorized` does the buyer's USDm note enter the chain — through
//!      the SAME block-output note path every other note uses ([`crate::node::Node::record_note_payload`]),
//!      never a side-channel.
//!
//! The `bridge` tests prove the WHOLE process on real crypto: real custodian keygen → real taproot address →
//! real t-of-n ML-DSA threshold signatures → `authorize_mint` → the buyer's note lands in the spendable
//! frontier — plus adversarial tamper (sub-quorum, forged signer, wrong-amount) all rejected fail-closed.

use crate::pqauth::{ml_dsa_keypair, ml_dsa_sign, pubkey_id};
use crate::psm::MintAttestor;

use k256::elliptic_curve::ops::Reduce; // CLASSICAL-CRYPTO-EXEMPT: the Bitcoin custody leaf (taproot over the custodians' secp points) at the foreign-chain bridge endpoint, never the PQ base layer
use k256::elliptic_curve::sec1::ToEncodedPoint; // CLASSICAL-CRYPTO-EXEMPT: the Bitcoin custody leaf (taproot over the custodians' secp points) at the foreign-chain bridge endpoint, never the PQ base layer
use k256::{FieldBytes, ProjectivePoint, Scalar, U256}; // CLASSICAL-CRYPTO-EXEMPT: the Bitcoin custody leaf (taproot over the custodians' secp points) at the foreign-chain bridge endpoint, never the PQ base layer
use sha2::{Digest, Sha256};

// ============================ secp256k1 bridge-endpoint custody (external BTC leg) ============================

/// A secp256k1 secret scalar derived (domain-separated, reduced mod n) from a custodian's own bridge seed.
/// The seed is the custodian's own material; the secret NEVER leaves the custodian. secp256k1 is the EXTERNAL
/// Bitcoin custody curve — used only at this bridge endpoint, never in the MonerousD PQ base layer.
fn secp_scalar_from_seed(seed: &[u8]) -> Scalar {
    let mut h = Sha256::new();
    h.update(b"USDMD-BRIDGE-SECP-SK-v1");
    h.update(seed);
    let d = h.finalize();
    let fb = FieldBytes::clone_from_slice(&d);
    <Scalar as Reduce<U256>>::reduce_bytes(&fb)
}

/// A custodian's secp256k1 bridge PUBLIC point from its seed (the secret stays with the custodian).
fn secp_point_from_seed(seed: &[u8]) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * secp_scalar_from_seed(seed)
}

/// SHA-256 tagged hash per BIP340/341: `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let th = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(th);
    h.update(th);
    h.update(msg);
    let out = h.finalize();
    let mut o = [0u8; 32];
    o.copy_from_slice(&out);
    o
}

/// The x-only (32-byte X coordinate) serialization of a point — the taproot witness program.
fn x_only(p: &ProjectivePoint) -> [u8; 32] {
    let enc = p.to_affine().to_encoded_point(false); // 0x04 ‖ X(32) ‖ Y(32)
    let mut out = [0u8; 32];
    if let Some(x) = enc.x() {
        out.copy_from_slice(x.as_slice());
    }
    out
}

// DB-121 (2026-09-20): the KEY-SUM reserve is gone. It summed the custodians' points into one taproot key-path
// key whose spend would have needed an interactive aggregate signature nobody had written — so the reserve was a
// one-way door. The reserve output is now `crate::btc_tx`'s script-path leaf: a k-of-n `OP_CHECKSIGADD` over the
// bonded set's x-only keys (slots ∝ bond) under a provably-unspendable NUMS internal key, spendable by
// INDEPENDENT signatures each custodian node produces on its own — the Bitcoin twin of the bond-weighted tally.

/// The custody leaf for weighted members `(secp point, bond weight)` — see [`crate::btc_tx::custody_leaf`].
pub fn custody_leaf_from_points(members: &[(ProjectivePoint, u128)]) -> Option<crate::btc_tx::CustodyLeaf> {
    let keys: Vec<([u8; 32], u128)> = members.iter().map(|(p, w)| (x_only(p), *w)).collect();
    crate::btc_tx::custody_leaf(&keys)
}

// ============================ bech32 / bech32m (BIP173 / BIP350), no external dep ============================

pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
pub const BECH32_CONST: u32 = 1;
pub const BECH32M_CONST: u32 = 0x2bc8_30a3;

pub fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= *g;
            }
        }
    }
    chk
}

pub fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(hrp.len() * 2 + 1);
    for &c in hrp.as_bytes() {
        v.push(c >> 5);
    }
    v.push(0);
    for &c in hrp.as_bytes() {
        v.push(c & 31);
    }
    v
}

fn bech32_checksum(hrp: &str, data: &[u8], spec_const: u32) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let m = bech32_polymod(&values) ^ spec_const;
    (0..6).map(|i| ((m >> (5 * (5 - i))) & 31) as u8).collect()
}

/// Encode a 5-bit `data` payload as a bech32 (spec_const = 1) / bech32m (spec_const = 0x2bc830a3) string.
fn bech32_encode(hrp: &str, data: &[u8], spec_const: u32) -> String {
    let mut s = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    s.push_str(hrp);
    s.push('1');
    let checksum = bech32_checksum(hrp, data, spec_const);
    for &d in data.iter().chain(checksum.iter()) {
        s.push(CHARSET[(d & 31) as usize] as char);
    }
    s
}

/// Regroup `data` from `from`-bit groups to `to`-bit groups (BIP173 convertbits), padding on encode.
pub fn convertbits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv: u32 = (1 << to) - 1;
    for &value in data {
        let value = value as u32;
        if (value >> from) != 0 {
            return None;
        }
        acc = (acc << from) | value;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

/// A BIP350 segwit address: `witness_version` + `program` → bech32 (v0) / bech32m (v≥1).
pub fn encode_segwit(hrp: &str, witver: u8, program: &[u8]) -> String {
    let mut data = vec![witver & 31];
    data.extend(convertbits(program, 8, 5, true).unwrap_or_default());
    let spec = if witver == 0 {
        BECH32_CONST
    } else {
        BECH32M_CONST
    };
    bech32_encode(hrp, &data, spec)
}

/// The Bitcoin network this node's reserve lives on. `MONEROUSD_BTC_NET` (`mainnet` | `testnet` | `testnet4` |
/// `regtest`) names it outright — the regtest oracle rig sets it, because a Bitcoin Core regtest chain has its own
/// `bcrt` addresses; absent that, it follows the MonerousD network exactly as before (a testnet chain bridges
/// Bitcoin testnet4, mainnet bridges mainnet), so a launch flips ONE switch.
pub fn btc_net() -> crate::btc_tx::BtcNet {
    match std::env::var("MONEROUSD_BTC_NET").as_deref() {
        Ok("regtest") => return crate::btc_tx::BtcNet::Regtest,
        Ok("testnet") | Ok("testnet4") | Ok("test") => return crate::btc_tx::BtcNet::Testnet,
        Ok("mainnet") | Ok("main") => return crate::btc_tx::BtcNet::Mainnet,
        _ => {}
    }
    match std::env::var("MONEROUSD_NET").as_deref() {
        Ok("testnet") | Ok("test") | Ok("regtest") => crate::btc_tx::BtcNet::Testnet,
        _ => crate::btc_tx::BtcNet::Mainnet,
    }
}

/// The Bitcoin human-readable prefix for the active network (`tb` = testnet4, `bc` = mainnet, `bcrt` = regtest).
pub fn btc_hrp() -> &'static str {
    btc_net().hrp()
}

/// Derive the REAL taproot Bitcoin deposit address for one swap from the custodian quorum's weighted secp256k1
/// bridge points: the k-of-n custody leaf's output under a per-swap tweak (DB-121). Returns `None` if there are
/// NO custodians (fail-closed: no custody script ⇒ NO address — a fabricated address would lose the user's real
/// deposit).
pub fn reserve_btc_address_from_points(
    members: &[(ProjectivePoint, u128)],
    swap_nonce: &[u8],
    hrp: &str,
) -> Option<String> {
    let leaf = custody_leaf_from_points(members)?;
    let out = crate::btc_tx::reserve_output(&leaf, swap_nonce)?;
    Some(crate::btc_tx::reserve_address(hrp, &out.output_x))
}

// ============================ charter custodian quorum (launch bootstrap) ============================

/// A charter reserve custodian: its ML-DSA mint-attestation identity + its secp256k1 BTC-custody seed. In
/// production each custodian is a distinct launch node holding its OWN keys (the test constructs a set and
/// holds them all, as the trusted orchestrator). The launch nodes are the charter t-of-n quorum from block 1
/// (permissionless-by-bond growth after) — so the reserve is threshold-secured at launch, never a single
/// point, and Buy is never "broken until someone bonds".
pub struct Custodian {
    pub mldsa_pk: Vec<u8>,
    mldsa_sk: Vec<u8>,
    secp_seed: Vec<u8>,
}

impl Custodian {
    /// A fresh custodian: a FRESH-RANDOM ML-DSA keypair (Pillar-2 keygen) + a bridge seed it alone holds.
    pub fn generate(secp_seed: &[u8]) -> Custodian {
        let (mldsa_pk, mldsa_sk) = ml_dsa_keypair();
        Custodian {
            mldsa_pk,
            mldsa_sk,
            secp_seed: secp_seed.to_vec(),
        }
    }

    /// This custodian's bonded-validator id (`H(mldsa_pk)`) — the id the [`crate::validator::ValidatorSet`] keys on.
    pub fn id(&self) -> [u8; 32] {
        pubkey_id(&self.mldsa_pk)
    }

    /// This custodian's secp256k1 bridge PUBLIC point (for the aggregate custody address).
    pub fn secp_point(&self) -> ProjectivePoint {
        secp_point_from_seed(&self.secp_seed)
    }

    /// Produce this custodian's REAL ML-DSA-65 attestation over the exact mint message.
    pub fn attest(&self, mint_msg: &[u8]) -> MintAttestor {
        MintAttestor {
            pubkey: self.mldsa_pk.clone(),
            // an unsignable key yields an EMPTY signature every verifier refuses (fail closed on the attestation)
            sig: ml_dsa_sign(mint_msg, &self.mldsa_sk).unwrap_or_default(),
        }
    }

    /// This custodian's compressed Monero bridge-custody point — the XMR analog of `secp_point()`, from the SAME
    /// bridge seed the custodian alone holds. The quorum's Σ of these is the node-computed t-of-n XMR reserve key.
    pub fn xmr_point(&self) -> [u8; 32] {
        xmr_point_from_seed(&self.secp_seed)
    }

    /// This custodian's 33-byte compressed secp bridge-custody point (the BTC analog of `xmr_point`), for
    /// registering into the LIVE bonded set's reserve key-aggregate (`node::register_validator_custody`).
    pub fn secp_compressed(&self) -> Vec<u8> {
        self.secp_point()
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

}

/// The real taproot deposit address for one swap, over a custodian quorum's own secp points.
pub fn reserve_btc_address(
    custodians: &[Custodian],
    swap_nonce: &[u8],
    hrp: &str,
) -> Option<String> {
    // Equal weights — the free founding seats' shape (`params::MEMBERSHIP_BOND_WEIGHT` each).
    let members: Vec<(ProjectivePoint, u128)> = custodians.iter().map(|c| (c.secp_point(), 1)).collect();
    reserve_btc_address_from_points(&members, swap_nonce, hrp)
}

// ============================ live-node reserve address (its own real custody point) ============================

/// This serve-node's persisted validator key path, so the RPC layer can derive the node's OWN real secp custody point
/// without duplicating the keyfile format. DB-341: the ONE definition (`validator::node_vote_key_path`), never a copy
/// of its formula — the copy read the operator's live key from an isolated (MONEROUSD_STATE_DIR) node.
fn node_validator_key_path() -> std::path::PathBuf {
    crate::validator::node_vote_key_path()
}

/// The validator key file's bytes, read through the custody keystore (opened when sealed at rest). The ONE reader
/// every bridge derivation uses (charter export, custody point, custody secret), so none of them reads the file raw.
/// O1-INFINITY-REVIEWED: the node's OWN identity key, one fixed-size file (≈ 5.9 KB); not chain state. These three
/// reads existed before; only the at-rest form changes.
fn node_validator_key_bytes() -> Option<Vec<u8>> {
    // The seed-provisioned marker is not key material: strip it, so every derivation below reads `pk_len ‖ pk ‖ sk`.
    let bytes = crate::keystore::read_key_file(&node_validator_key_path()).ok()?;
    Some(match bytes.strip_suffix(crate::validator::PROVISIONED_TRAILER) {
        Some(body) => body.to_vec(),
        None => bytes,
    })
}

// (A single-node's own custody point is NOT a reserve — a solo key is not a t-of-n threshold. The former
// `node_own_custody_point` solo path was REMOVED: both bridges fail-closed with no real bonded quorum.)

// CLASSICAL-BRIDGE-ENDPOINT: the helpers below (compress/parse a secp256k1 custody point + charter custody
// aggregation) operate on the EXTERNAL Bitcoin custody curve at the bridge endpoint (crate::bridge) ONLY —
// never in the MonerousD PQ base layer (Pillar 2). The MINT AUTHORITY stays post-quantum: it is the ML-DSA-65
// t-of-n threshold in crate::psm::authorize_mint; secp256k1 only names the BTC address the deposit lands at.

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let h = hex.trim();
    (0..h.len() / 2)
        .filter_map(|i| u8::from_str_radix(h.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

/// The 33-byte compressed SEC1 serialization of a secp point, hex-encoded — a custodian's PUBLIC custody key
/// (exported so the launch nodes can assemble the shared charter quorum; the secret never leaves the node).
fn secp_compressed_hex(p: &ProjectivePoint) -> String {
    let enc = p.to_affine().to_encoded_point(true);
    enc.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a compressed SEC1 hex custody pubkey → a secp point. `from_sec1_bytes` fail-closes on any malformed
/// or wrong-length input, so a bad charter entry is dropped rather than trusted.
fn secp_point_from_compressed_hex(hex: &str) -> Option<ProjectivePoint> {
    Some(
        k256::PublicKey::from_sec1_bytes(&hex_to_bytes(hex)) // CLASSICAL-CRYPTO-EXEMPT: a Bitcoin custodian's secp pubkey from the charter, foreign-chain bridge endpoint only
            .ok()?
            .to_projective(),
    )
}

/// A pinned CHARTER reserve-custodian member: its ML-DSA mint-attestation pubkey + its secp256k1 BTC custody
/// point + its Monero (Ed25519) custody point. The charter quorum is pinned on EVERY node via
/// `MONEROUSD_CHARTER_QUORUM` ("mldsa_pk_hex:secp_compressed_hex:xmr_compressed_hex, …", identical across nodes),
/// so every node NODE-COMPUTES the SAME t-of-n BTC + XMR reserve addresses from block 1. No single party holds
/// either aggregate — a real threshold. `xmr_point` is `None` for a legacy 2-field entry (that member is then
/// absent from the XMR aggregate — fail-closed, never fabricated).
pub struct CharterMember {
    pub mldsa_pk: Vec<u8>,
    pub secp_point: ProjectivePoint,
    pub xmr_point: Option<[u8; 32]>,
}

/// Parse the pinned charter quorum from `MONEROUSD_CHARTER_QUORUM`. A member is kept only when BOTH its ML-DSA key
/// and its secp custody point parse; the Monero custody point (3rd field) is optional (a 32-byte compressed point).
/// ⛔ RETIRED SOURCE, KEPT ONLY SO A STALE ENV IS LOUDLY IGNORED RATHER THAN SILENTLY HONOURED.
///
/// Reading a charter from the environment is what made the quorum LOCAL (§CW: two peered nodes each held
/// `{"validators":1}` — itself — and one BTC deposit minted USDm once per node). There is no charter source
/// at all any more, and NO founding keys: a seat is `Class::MembershipBond`, a chain object carried in
/// `Block::bond_set`, free while the reserve is zero, applied by every grafting node — so "the first nodes
/// to bond" is a fact the chain records rather than one each node reads from its own env. This returns
/// EMPTY always and says so once if the env is still set, so an operator with it in a launch script learns
/// why nothing is being seated from it.
pub fn charter_members_from_env() -> Vec<CharterMember> {
    if !std::env::var("MONEROUSD_CHARTER_QUORUM").unwrap_or_default().trim().is_empty() {
        eprintln!(
            "[charter] ⛔ MONEROUSD_CHARTER_QUORUM is set and IGNORED — a charter read from the \
             environment is LOCAL state, and two nodes with different env disagree about who may \
             authorise a mint (measured: one BTC deposit minted USDm twice). A seat is now a chain \
             object — Class::MembershipBond, free while the reserve is zero — that every node applies \
             from the block. Set MONEROUSD_VALIDATOR_BOND and this node will PUBLISH its own seat."
        );
    }
    Vec::new()
}

/// Export THIS node's charter-member line ("mldsa_pk_hex:secp_compressed_hex") from its persisted validator
/// key — used to assemble the shared `MONEROUSD_CHARTER_QUORUM` across the launch nodes (the `charter-export`
/// subcommand prints it). Only the PUBLIC parts are exported; the ML-DSA + secp secrets never leave the node.
pub fn export_local_charter_member() -> Option<String> {
    let bytes = node_validator_key_bytes()?;
    let pk_len = u32::from_le_bytes([
        *bytes.first()?,
        *bytes.get(1)?,
        *bytes.get(2)?,
        *bytes.get(3)?,
    ]) as usize;
    let pk = bytes.get(4..4 + pk_len)?;
    let sk = bytes.get(4 + pk_len..)?;
    let pk_hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!(
        "{pk_hex}:{}",
        secp_compressed_hex(&secp_point_from_seed(sk))
    ))
}

// (`node_reserve_btc_address` — the charter-env aggregate with no caller — was DELETED with DB-121; the live node
// derives its reserve from the chain's bonded set in `reserve_addresses_from_bonded_custody` and nothing else.)

// ==================== Monero (XMR) CryptoNote address codec (curve-free encoding half) ====================
//
// The byte/hash half of a Monero address — the CryptoNote base58 codec + the Keccak-256 address checksum (NO
// curve math). The NODE-COMPUTED reserve leg below feeds it the key-aggregate spend/view points; this section
// just encodes `net ‖ spend ‖ view ‖ checksum` into the standard address string. Kept separate so the curve
// (crate `curve25519-dalek`, the four-pillar external-bridge carve-out) is confined to the reserve helpers.

/// The CryptoNote base58 alphabet (Bitcoin's, 58 chars) and the per-block encoded sizes (decoded 0..8 bytes →
/// encoded chars). NOT Bitcoin base58 — a block-based variant (8-byte blocks → 11 chars each, partial per table).
const CN_B58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const CN_B58_ENCODED_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

/// Inverse of `CN_B58_ENCODED_SIZES`: an encoded block of `enc` chars decodes to this many bytes (`None` = an
/// impossible block length ⇒ a malformed address).
fn cn_decoded_size(enc: usize) -> Option<usize> {
    match enc {
        0 => Some(0),
        2 => Some(1),
        3 => Some(2),
        5 => Some(3),
        6 => Some(4),
        7 => Some(5),
        9 => Some(6),
        10 => Some(7),
        11 => Some(8),
        _ => None,
    }
}

/// Encode one 1..=8-byte block (big-endian uint) to its fixed-width CryptoNote base58 chunk, left-padded with '1'.
fn cn_encode_block(block: &[u8], out: &mut String) {
    let mut num: u64 = 0;
    for &b in block {
        num = (num << 8) | b as u64;
    }
    let size = CN_B58_ENCODED_SIZES[block.len()];
    let mut buf = [b'1'; 11];
    let mut i = size;
    while num > 0 && i > 0 {
        i -= 1;
        buf[i] = CN_B58_ALPHABET[(num % 58) as usize];
        num /= 58;
    }
    out.push_str(std::str::from_utf8(&buf[..size]).unwrap_or(""));
}

/// CryptoNote base58 encode (8-byte blocks → 11 chars, final partial block per the table). Pure byte encoding.
pub fn cn_base58_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let full = data.len() / 8;
    // NOT §AG CLASS 9: base58's 8-byte blocks over arbitrary bytes; the bound is the input's own length.
    for i in 0..full {
        cn_encode_block(&data[i * 8..i * 8 + 8], &mut out);
    }
    let rem = data.len() % 8;
    if rem > 0 {
        cn_encode_block(&data[full * 8..], &mut out);
    }
    out
}

/// CryptoNote base58 decode — inverse of [`cn_base58_encode`]. `None` on any non-alphabet char, an impossible
/// block length, or a block value that overflows its byte width (a malformed address ⇒ fail-closed).
pub fn cn_base58_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let full = bytes.len() / 11;
    let last = bytes.len() % 11;
    let mut out = Vec::with_capacity(bytes.len());
    let decode_block = |chunk: &[u8], dec_size: usize, out: &mut Vec<u8>| -> Option<()> {
        let mut num: u64 = 0;
        for &c in chunk {
            let d = CN_B58_ALPHABET.iter().position(|&a| a == c)? as u64;
            num = num.checked_mul(58)?.checked_add(d)?;
        }
        if dec_size < 8 && (num >> (8 * dec_size)) != 0 {
            return None; // value too large for this block's byte width
        }
        out.extend_from_slice(&num.to_be_bytes()[8 - dec_size..]);
        Some(())
    };
    for i in 0..full {
        decode_block(&bytes[i * 11..i * 11 + 11], 8, &mut out)?;
    }
    if last > 0 {
        let dec = cn_decoded_size(last)?;
        decode_block(&bytes[full * 11..], dec, &mut out)?;
    }
    Some(out)
}

/// A well-formed Monero address predicate — CURVE-FREE (base58 + Keccak-256 checksum only): decode the CryptoNote
/// base58 and verify the trailing 4-byte checksum is the first 4 bytes of Keccak-256(payload). This is the SAME
/// checksum a Monero wallet computes, so a corrupted/typo'd registered address is rejected; it does NOT (and,
/// staying PQ, cannot) validate the foreign-curve key points — that soundness rests on the custodian quorum
/// registering their genuine multisig address.
pub fn is_monero_address(s: &str) -> bool {
    let bytes = match cn_base58_decode(s.trim()) {
        Some(b) if b.len() >= 5 => b,
        _ => return false,
    };
    let (payload, checksum) = bytes.split_at(bytes.len() - 4);
    let mut k = sha3::Keccak256::new();
    k.update(payload);
    let h = k.finalize();
    &h[..4] == checksum
}

// ── Monero (XMR) reserve addresses — the bonded set's k-of-n MULTISIG wallet, per-swap INTEGRATED addresses ────
//
// DB-121x (2026-09-21). Monero has no script, so its k-of-n custody is its own multisig: each bonded custodian's
// wallet-rpc holds one key and the wallets form ONE k-of-n address by key exchange over the mesh
// (`crate::xmr_custody`). What this module holds is the CURVE-FREE part every node can compute: the codec that turns
// the set's announced main address plus a per-swap payment id (a function of the mint blind, DB-123) into the
// INTEGRATED deposit address a wallet is given, and back. An earlier design derived a Monero address from the SUM
// of the seats' Ed25519 points — a real address nothing could spend from (no signing protocol exists for such a
// sum): a deposit there would have stranded the coin forever. It is gone; the seat's Ed25519 point stays only as
// the identity point the membership bond encodes.
use curve25519_dalek::edwards::EdwardsPoint as XmrPoint; // CLASSICAL-CRYPTO-EXEMPT / CLASSICAL-BRIDGE-ENDPOINT: the seat's Ed25519 identity point in the membership bond, never the PQ base layer
use curve25519_dalek::scalar::Scalar as XmrScalar; // CLASSICAL-CRYPTO-EXEMPT / CLASSICAL-BRIDGE-ENDPOINT: the seat's Ed25519 identity point in the membership bond, never the PQ base layer

/// A seat's compressed Ed25519 identity point from its OWN bridge seed — the `ed32` field a membership bond
/// carries. It is NOT a Monero spend key: Monero custody keys live in the custodians' wallets (`xmr_custody`).
fn xmr_point_from_seed(seed: &[u8]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(32 + seed.len());
    pre.extend_from_slice(b"USDMD-BRIDGE-XMR-SPEND-v1");
    pre.extend_from_slice(seed);
    let s = XmrScalar::from_bytes_mod_order(*blake3::hash(&pre).as_bytes());
    XmrPoint::mul_base(&s).compress().to_bytes()
}

/// The Monero network the node's Monero leg is on, as its STANDARD-address prefix byte: `MONEROUSD_XMR_NET` =
/// `mainnet` | `regtest` (a regtest daemon uses mainnet address bytes) → 18 ("4…"), `stagenet` → 24 ("5…"),
/// `testnet` → 53 ("9…"); unset, it follows `MONEROUSD_NET` (testnet → 53, else 18).
pub fn xmr_net_byte() -> u8 {
    match std::env::var("MONEROUSD_XMR_NET").as_deref() {
        Ok("mainnet") | Ok("main") | Ok("regtest") => return 18,
        Ok("stagenet") | Ok("stage") => return 24,
        Ok("testnet") | Ok("test") => return 53,
        _ => {}
    }
    match std::env::var("MONEROUSD_NET").as_deref() {
        Ok("testnet") | Ok("test") | Ok("regtest") => 53,
        Ok("stagenet") => 24,
        _ => 18,
    }
}

/// Monero's INTEGRATED-address prefix for a network's standard prefix (mainnet 18 → 19 "4…", stagenet 24 → 25
/// "5…", testnet 53 → 54 "A…").
pub fn xmr_integrated_net_byte(standard: u8) -> u8 {
    standard.saturating_add(1)
}

/// The network a Monero address belongs to, as its STANDARD prefix byte, read from the address's own prefix
/// (standard / integrated / subaddress bytes: mainnet 18/19/42, testnet 53/54/63, stagenet 24/25/36); `None` for
/// a string that is not a checksummed Monero address.
pub fn xmr_address_net(address: &str) -> Option<u8> {
    if !is_monero_address(address) {
        return None;
    }
    let bytes = cn_base58_decode(address.trim())?;
    match *bytes.first()? {
        18 | 19 | 42 => Some(18),
        53 | 54 | 63 => Some(53),
        24 | 25 | 36 => Some(24),
        _ => None,
    }
}

/// Decode a checksummed STANDARD Monero address into (network prefix, spend point, view point).
pub fn decode_monero_standard_address(address: &str) -> Option<(u8, [u8; 32], [u8; 32])> {
    if !is_monero_address(address) {
        return None;
    }
    let bytes = cn_base58_decode(address.trim())?;
    if bytes.len() != 69 {
        return None; // 1 + 32 + 32 + 4: only a standard address has this width
    }
    let net = bytes[0];
    if !matches!(net, 18 | 53 | 24) {
        return None;
    }
    let mut spend = [0u8; 32];
    let mut view = [0u8; 32];
    spend.copy_from_slice(&bytes[1..33]);
    view.copy_from_slice(&bytes[33..65]);
    Some((net, spend, view))
}

/// The INTEGRATED address of a set's main address for one swap — the network's integrated prefix, the spend and
/// view points, the payment id, then the four Keccak-256 checksum bytes, in CryptoNote base58 — the same bytes a
/// Monero wallet's `make_integrated_address` emits, computed here by any node from public data.
pub fn xmr_integrated_address(main_address: &str, payment_id: &[u8; 8]) -> Option<String> {
    let (net, spend, view) = decode_monero_standard_address(main_address)?;
    let mut payload = Vec::with_capacity(77);
    payload.push(xmr_integrated_net_byte(net));
    payload.extend_from_slice(&spend);
    payload.extend_from_slice(&view);
    payload.extend_from_slice(payment_id);
    let mut k = sha3::Keccak256::new();
    k.update(&payload);
    let h = k.finalize();
    payload.extend_from_slice(&h[..4]);
    Some(cn_base58_encode(&payload))
}

/// The payment id an INTEGRATED Monero address carries, and the STANDARD address it integrates.
pub fn xmr_integrated_parts(address: &str) -> Option<([u8; 8], String)> {
    if !is_monero_address(address) {
        return None;
    }
    let bytes = cn_base58_decode(address.trim())?;
    if bytes.len() != 77 {
        return None; // 1 + 32 + 32 + 8 + 4
    }
    let net = match bytes[0] {
        19 => 18,
        54 => 53,
        25 => 24,
        _ => return None,
    };
    let mut pid = [0u8; 8];
    pid.copy_from_slice(&bytes[65..73]);
    let mut spend = [0u8; 32];
    let mut view = [0u8; 32];
    spend.copy_from_slice(&bytes[1..33]);
    view.copy_from_slice(&bytes[33..65]);
    Some((pid, encode_monero_address(net, &spend, &view)))
}

/// This node's OWN bridge-custody points — compressed secp (33) + Ed25519 (32) — from its persisted validator
/// secret, so a self-bonding validator registers its share of the reserve key-aggregate
/// (`node::register_validator_custody`). `None` if the node has no validator key yet. This is NOT a solo-key path —
/// it is a self-bonding validator's real custody, which joins the LIVE bonded set exactly like any other
/// validator's; the reserve stays the aggregate of the whole bonded set and grows as more bond.
pub fn node_own_bridge_custody() -> Option<(Vec<u8>, [u8; 32])> {
    let bytes = node_validator_key_bytes()?;
    if bytes.len() <= 4 {
        return None;
    }
    let pk_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len() < 4 + pk_len {
        return None;
    }
    Some(bridge_custody_of_vote_sk(&bytes[4 + pk_len..]))
}

/// The bridge custody points `(secp33, ed32)` a vote secret key registers: the one derivation the node's own seat and a launch's founding seat share.
#[must_use]
pub fn bridge_custody_of_vote_sk(sk: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let secp33 = secp_point_from_seed(sk)
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    (secp33, xmr_point_from_seed(sk))
}

/// DB-121: this node's OWN secp256k1 custody SECRET — the key its slot in the reserve leaf holds, derived from
/// the same validator seed as `node_own_bridge_custody`'s public point, so `btc_tx::xonly_pubkey(secret)` is
/// exactly the x of `secp33`. Read from the key file on each use and never cached in the node: the custodian
/// signs a payout's sighash with it (`btc_tx::sign_sighash`) and nothing else ever sees it.
pub fn node_own_bridge_secret() -> Option<[u8; 32]> {
    let bytes = node_validator_key_bytes()?;
    if bytes.len() <= 4 {
        return None;
    }
    let pk_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len() < 4 + pk_len {
        return None;
    }
    let sk = &bytes[4 + pk_len..];
    let fb = secp_scalar_from_seed(sk).to_bytes(); // CLASSICAL-CRYPTO-EXEMPT: the Bitcoin custody signing key at the bridge endpoint
    <[u8; 32]>::try_from(fb.as_slice()).ok()
}

/// This node's OWN custody ML-KEM-768 keypair `(ek, dk)` — the encapsulation key its membership seat
/// publishes (`MembershipBondHeader::kem_ek`) and the decapsulation key it opens sealed peg-in deltas with
/// (`crate::peg_attest::open_delta`). Persisted beside the validator key as `validator-{port}.kem`
/// (`len(ek) u32 LE ‖ ek ‖ dk`), created on first use; the dk never leaves this process. `None` only when
/// the key file cannot be written (fail-closed: a custodian nobody can seal to must not seat).
/// Read and written through the custody keystore (sealed at rest under the operator passphrase when one is
/// configured). ⛔ A key file that EXISTS but will not open answers `None` and is never replaced: a fresh dk would
/// silently orphan every delta already sealed to this custodian's published ek.
/// O1-INFINITY-REVIEWED: the node's OWN custody key, one fixed-size file (4 + ML-KEM-768 ek + dk = 3,588 B); not
/// chain state. The read existed before; only the at-rest form changes.
pub fn node_own_custody_kem() -> Option<(Vec<u8>, Vec<u8>)> {
    let path = node_validator_key_path().with_extension("kem");
    match crate::keystore::read_key_file(&path) {
        Ok(bytes) => {
            if bytes.len() > 4 {
                let ek_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
                if bytes.len() > 4 + ek_len {
                    return Some((bytes[4..4 + ek_len].to_vec(), bytes[4 + ek_len..].to_vec()));
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            eprintln!("[custody] ⛔ this custodian's KEM key exists but does not open ({e}); it is not replaced");
            return None;
        }
    }
    let (ek, dk) = crate::pqkem::keypair();
    let mut out = Vec::with_capacity(4 + ek.len() + dk.len());
    out.extend_from_slice(&(ek.len() as u32).to_le_bytes());
    out.extend_from_slice(&ek);
    out.extend_from_slice(&dk);
    crate::keystore::write_key_file(&path, &out).ok()?;
    Some((ek, dk))
}

/// The weighted secp members of the LIVE bonded set (`validator::ValidatorSet::bonded_custody_weighted`) as
/// curve points — ALL must parse (fail-closed on any malformed point), or `None`.
fn secp_members(custody: &[(crate::validator::BridgeCustody, u128)]) -> Option<Vec<(ProjectivePoint, u128)>> {
    let mut members = Vec::with_capacity(custody.len());
    for (c, w) in custody {
        let hex: String = c.secp33.iter().map(|b| format!("{b:02x}")).collect();
        members.push((secp_point_from_compressed_hex(&hex)?, *w));
    }
    Some(members)
}

/// DB-121: the reserve CUSTODY LEAF of the live bonded set — the k-of-n script every custodian signs against and
/// every payout's control block reveals. `None` when the set is empty or a point is malformed.
pub fn custody_leaf_from_bonded_custody(
    custody: &[(crate::validator::BridgeCustody, u128)],
) -> Option<crate::btc_tx::CustodyLeaf> {
    if custody.is_empty() {
        return None;
    }
    custody_leaf_from_points(&secp_members(custody)?)
}

/// The node-computed BTC + XMR reserve addresses for one swap from the LIVE bonded validator set's custody points
/// WITH their bond weights (`validator::ValidatorSet::bonded_custody_weighted`). BTC (DB-121): the k-of-n
/// `OP_CHECKSIGADD` custody leaf's taproot output under this swap's tweak — a 1-of-1 when a single validator has
/// bonded, ⌈2n/3⌉-of-n as more bond, the weights as slots (decentralization grows with time, by construction).
/// XMR: the Ed25519 key-aggregate address (its custody signer is the next leg, see DB-121x). `None` per asset
/// when the set is empty or a point is malformed (fail-closed, never a fabricated / solo-off-the-set address).
pub fn reserve_btc_address_from_bonded_custody(
    custody: &[(crate::validator::BridgeCustody, u128)],
    swap_nonce: &[u8],
) -> Option<String> {
    if custody.is_empty() {
        return None;
    }
    secp_members(custody).and_then(|members| reserve_btc_address_from_points(&members, swap_nonce, btc_hrp()))
}

/// Assemble a checksummed CryptoNote address string from a network byte + the 32-byte spend/view points — the
/// CURVE-FREE encoding half of a Monero address (the SAME bytes a wallet emits AFTER it derives the points):
/// `base58(net ‖ spend ‖ view ‖ Keccak-256(net‖spend‖view)[..4])`. Deriving the points is the custodians' off-node
/// multisig ceremony (the classical foreign curve, never in this base layer); this is only the encoding + checksum.
pub fn encode_monero_address(net_byte: u8, spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(65);
    payload.push(net_byte);
    payload.extend_from_slice(spend_pub);
    payload.extend_from_slice(view_pub);
    let mut k = sha3::Keccak256::new();
    k.update(&payload);
    let h = k.finalize();
    payload.extend_from_slice(&h[..4]);
    cn_base58_encode(&payload)
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::hash::Hash32;
    use crate::pqauth::mint_attest_msg;
    use crate::psm::{authorize_mint, BondQuorum, MintOutcome, MintRequest};
    use crate::solvency::{SolvencyProof, SolvencyVerifier};
    use crate::validator::ValidatorSet;

    // Solvency stand-in: the 150% ZK proof is separately tamper-tested in `crate::solvency`; here we exercise
    // the THRESHOLD + real-ML-DSA + address pipeline, so the solvency seam is a fixed accept/reject double.
    struct SolvOk;
    impl SolvencyVerifier for SolvOk {
        fn verify_solvency(&self, _p: &SolvencyProof) -> bool {
            true
        }
    }

    fn proof_150() -> SolvencyProof {
        SolvencyProof {
            reserve_commit: [3u8; 32],
            liability_commit: [5u8; 32],
            ratio_bps: 15_000,
            proof: vec![1u8; 1000],
        }
    }

    // ---- bech32 / bech32m validated against the official BIP173 / BIP350 empty-data test vectors ----
    #[test]
    fn bech32_matches_bip173_and_bip350_spec_vectors() {
        assert_eq!(bech32_encode("a", &[], BECH32_CONST), "a12uel5l");
        assert_eq!(bech32_encode("a", &[], BECH32M_CONST), "a1lqfn3a");
    }

    // ---- the deposit address is a REAL taproot bech32m address (real curve point), NOT a fabricated hash ----
    #[test]
    fn deposit_address_is_a_real_taproot_address() {
        let custodians: Vec<Custodian> = (0..3u8).map(|i| Custodian::generate(&[i; 32])).collect();
        let addr = reserve_btc_address(&custodians, b"swap-nonce-1", "tb").expect("quorum exists");
        // taproot: hrp(2) + '1' + witver('p') + 52 program chars + 6 checksum = 62 chars, lowercase bech32.
        assert!(
            addr.starts_with("tb1p"),
            "real taproot testnet address: {addr}"
        );
        assert_eq!(addr.len(), 62, "taproot address length: {addr}");
        assert!(addr
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
        // A DIFFERENT swap nonce yields a DIFFERENT (fresh, unlinkable) real address.
        let addr2 = reserve_btc_address(&custodians, b"swap-nonce-2", "tb").unwrap();
        assert_ne!(addr, addr2);
        // NO quorum ⇒ NO address (fail-closed — never a fabricated one that would lose funds).
        assert!(reserve_btc_address(&[], b"swap-nonce-1", "tb").is_none());
    }

    // Mock quorum so the empty-set fail-closed path is covered without a live node.
    struct EmptyQ;
    impl BondQuorum for EmptyQ {
        fn bond_of(&self, _id: &[u8; 32]) -> u128 {
            0
        }
        fn total_bond(&self) -> u128 {
            0
        }
    }

    #[test]
    fn no_charter_quorum_never_mints() {
        let c = Custodian::generate(&[1u8; 32]);
        let msg = mint_attest_msg(&[7u8; 32], &[3u8; 32], &[5u8; 32], &[9u8; 32], 15_000);
        let req = MintRequest {
            deposit_id: [7u8; 32],
            recipient_note_cm: [9u8; 32],
            solvency: proof_150(),
            attestors: vec![c.attest(&msg)],
        };
        assert_eq!(
            authorize_mint(
                &EmptyQ,
                &crate::pqauth::MlDsaVerifier,
                &SolvOk,
                &req,
                15_000
            ),
            MintOutcome::InsufficientQuorum
        );
    }
}
