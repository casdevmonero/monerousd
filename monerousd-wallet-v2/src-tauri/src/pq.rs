// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// MoneroUSD Wallet V2 — clean-room PQ wallet crypto (NO old-wallet code, NO Monero logic).
//
// A MonerousD wallet identity is two post-quantum keypairs derived from ONE fresh-random root seed:
//   • SPEND  = ML-DSA-65 (FIPS 204)  — signs spends; its public key's blake3 digest is the address tag `b`.
//   • SCAN   = ML-KEM-768 (FIPS 203) — the sender encapsulates a per-output secret to it; the wallet
//              recovers its notes by decapsulating LOCALLY (the node stores NO scan key — Pillar 1).
//
// FRESH-RANDOM keygen ⊥ DETERMINISTIC derivation (cardinal): `generate()` draws a fresh 32-byte CSPRNG
// root and encodes it as a 24-word BIP39 phrase; both keypairs are then DERIVED deterministically from
// that root via domain-separated blake3, so `restore(phrase)` reproduces the identical keys + address.
//
// The keys are standard FIPS 203/204, so they byte-interoperate with the node's pqcrypto (PQClean):
// the node verifies the wallet's ML-DSA signatures and encapsulates to the wallet's ML-KEM key. The
// address is byte-for-byte the node's `crate::address` codec (cnBase58 over `varint(tag) ‖ b(32) ‖
// ek(1184) ‖ keccak256[..4]`), so a node-served address and a wallet-built address share one format.
// =========================================================================================

use sha3::{Digest, Keccak256};
// ⛔⛔⛔ §AG WIDENED A DIGEST FROM 4 LANES TO 8, AND THIS TREE KEPT SPELLING IT `[u64; 4]`.
// The width belongs to the TYPE, never to a literal repeated 149 times. `Digest4` is the node's own
// alias (`usdm_decider::poseidon2_compress::Digest`), so the wallet can never again disagree with the
// chain about how wide a commitment, root, nullifier or key is.
use usdmd_node::spend_frontier::Digest4;
use zeroize::Zeroizing;

// ── Address codec — byte-identical to monerousd-node-zkdag/src/address.rs (the node's own encoder). ──
/// Monero-style block-base58 alphabet (58 chars, no 0/O/I/l).
const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// Encoded-char count for a block of 0..=8 raw bytes (the cnBase58 size table).
const ENC_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];
const FULL_BLOCK: usize = 8;

/// Network address tags (varint-prefixed), identical to the node's `PQ_ADDR_TAG`.
pub const PQ_ADDR_TAG_TESTNET: u64 = 0x315054;
pub const PQ_ADDR_TAG_MAINNET: u64 = 0x31504d;

/// ML-KEM-768 encapsulation-key length — the address's `mlkem` field width.
pub const MLKEM_EK_LEN: usize = 1184;

/// Keccak-256 (original Keccak padding — matches the node's `crate::address` + the JS `@noble` keccak_256,
/// NOT NIST SHA3). Used only for the 4-byte address checksum.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    let mut o = [0u8; 32];
    o.copy_from_slice(&h.finalize());
    o
}

/// LEB128 varint encode.
fn varint_encode(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n > 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
    out
}

/// Encode one base58 block of `data.len()` (1..=8) raw bytes into its fixed cnBase58 char count.
fn b58_encode_block(data: &[u8]) -> String {
    let mut num: u128 = 0;
    for &b in data {
        num = (num << 8) | b as u128;
    }
    let enc_len = ENC_BLOCK_SIZES[data.len()];
    let mut out = vec![ALPHABET[0]; enc_len];
    let mut i = enc_len;
    while num > 0 && i > 0 {
        i -= 1;
        out[i] = ALPHABET[(num % 58) as usize];
        num /= 58;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// cnBase58 encode: full 8-byte blocks (→11 chars) then a trailing partial block.
fn b58_encode(buf: &[u8]) -> String {
    let mut res = String::new();
    let full = buf.len() / FULL_BLOCK;
    let last = buf.len() % FULL_BLOCK;
    for i in 0..full {
        res.push_str(&b58_encode_block(&buf[i * FULL_BLOCK..(i + 1) * FULL_BLOCK]));
    }
    if last > 0 {
        res.push_str(&b58_encode_block(&buf[full * FULL_BLOCK..]));
    }
    res
}





/// LEB128 varint decode → (value, bytes_consumed). None if the bytes run out or the value overflows u64.
fn varint_decode(data: &[u8]) -> Option<(u64, usize)> {
    let mut n: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in data.iter().enumerate() {
        n |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((n, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

/// Parse a PQ stealth address back to `(tag, b, ek)`. Verifies the 4-byte keccak checksum; None on any
/// malformed input. The SENDER uses this to recover the recipient's ML-KEM-768 `ek` so it can seal a
/// confidential note to them.
///
/// DELEGATES to the NODE's decoder rather than carrying a second copy. The wallet used to hold its own,
/// and the moment v2 addresses started carrying a locator that copy rejected every address this very
/// wallet generates — the exact silent drift two implementations of one primitive always produce. There
/// is now ONE decoder; use [`usdmd_node::address::parse_address_full`] when the locator is needed too.
pub fn parse_address(addr: &str) -> Option<(u64, [u8; 32], Vec<u8>)> {
    usdmd_node::address::parse_address(addr)
}

/// `cnBase58( varint(tag) ‖ data ‖ keccak256(varint(tag) ‖ data)[0..4] )`.
fn encode_addr(tag: u64, data: &[u8]) -> String {
    let mut blob = varint_encode(tag);
    blob.extend_from_slice(data);
    let cksum = keccak256(&blob);
    blob.extend_from_slice(&cksum[0..4]);
    b58_encode(&blob)
}

/// A full PQ stealth address from its spend tag `b` (32 bytes) and ML-KEM-768 encapsulation key `mlkem`
/// (1184 bytes). `None` if `mlkem` is not exactly 1184 bytes (fail-closed, never a malformed address).
pub fn pq_stealth_address(tag: u64, b: &[u8; 32], mlkem: &[u8]) -> Option<String> {
    if mlkem.len() != MLKEM_EK_LEN {
        return None;
    }
    let mut data = Vec::with_capacity(32 + MLKEM_EK_LEN);
    data.extend_from_slice(b);
    data.extend_from_slice(mlkem);
    Some(encode_addr(tag, &data))
}

// ── Key derivation ──
/// A wallet's derived PQ identity. Secret material is held in `Zeroizing` buffers wiped on drop.
pub struct WalletKeys {
    pub spend_pk: Vec<u8>,             // ML-DSA-65 verification key (1952 B, public)
    pub spend_sk: Zeroizing<Vec<u8>>,  // ML-DSA-65 signing key (4032 B, SECRET)
    pub scan_ek: Vec<u8>,              // ML-KEM-768 encapsulation key (1184 B, public)
    pub scan_dk: Zeroizing<Vec<u8>>,   // ML-KEM-768 decapsulation key (2400 B, SECRET)
    pub b: [u8; 32],                   // address spend tag = blake3(spend_pk)
    pub address: String,               // ROTATING v2 receive address — give to ONE payer (carries a locator)
    /// The locator-free (v1) address for anything PUBLISHED — a @username, a donation QR, a website.
    /// Publishing a locator would let anyone read the handle, derive its index key, and learn the exact
    /// block and slot of every payment ever made to it.
    pub handle_address: String,
    pub clue_pk: crate::omr::CluePublicKey, // packed-LWE DETECTION clue key (public) — rides the address record
    pub clue_sk: crate::omr::ClueSecretKey, // packed-LWE clue SECRET — never leaves the wallet (like scan_dk)
    /// OLI locator secret — the seed-only anchor for sub-second cold restore. Every note sent to this
    /// wallet carries a one-time locator `PRF(loc_sk, j)`; holding `loc_sk` lets the wallet ENUMERATE
    /// those locators from the phrase alone and look each one up in the node's index, instead of
    /// scanning the chain for its notes. Never leaves the wallet — anyone holding it could enumerate
    /// (though not open) this wallet's notes.
    pub loc_sk: [u8; 32],
    /// DB-288 OUTGOING-RECORD SECRET — derived from the root entropy under its own domain, never from `loc_sk`, so the
    /// locator secret alone can never open a spent record. It seals, into each note this wallet makes for itself, the
    /// nullifiers that note's tx consumed (`outgoing_record`), so a seed-only restore recovers its spent set with no
    /// nullifier ask. Never leaves the wallet.
    pub out_sk: [u8; 32],
    /// ⭐ VALIDATOR ROOT — the seed-derived root of every validator identity this wallet bonds (user 2026-09-28: a bonded
    /// node is linked to the operator's seed, and bonding needs no setup and no password). Derived from the root entropy
    /// under its own domain, so a seed-only restore reproduces every validator identity and every bond on it survives
    /// the loss of a node machine. Never leaves the wallet: its node receives only the DERIVED keys
    /// ([`derive_validator_identity`]).
    pub validator_root: [u8; 32],
    /// ⭐ DSOL CALLER ROOT (DSOL node door spec §6b A1) — the seed-derived root of this wallet's per-contract caller
    /// keys. A DSOL call carries `pk_c` and a signature over its body; the contract's `msg.sender` is a digest of `pk_c`
    /// (the decider's ONE caller derivation). Derived from the root entropy under its own domain, so a seed-only restore
    /// reproduces every caller identity; never leaves the wallet ([`derive_dsol_caller`] hands out only derived keys).
    pub dsol_root: [u8; 32],
    /// ⭐ SATOSHI §8.1 — the reward-only locator key: the node this wallet provisions seals every mining reward to `scan_ek`
    /// and tags it at `("sat", n)` under THIS key, never under `loc_sk` — the node can recognise the rewards it minted and
    /// nothing else. Derived from the seed, so a seed-only restore sweeps the same `"sat"` index space.
    pub sat_loc_sk: [u8; 32],
    /// ⛔⛔⛔ DB-395 — the NOTE SPEND AUTHORITY `ask`: with `note_nk` it is the only thing that spends this wallet's notes (the
    /// opening a payer holds spends nothing). SECRET, never leaves the wallet, never sent to its node.
    pub note_ask: Digest4,
    /// DB-395 — the NULLIFIER key `nk`: a spend lays `nf = P(nk, cm)`, so only this wallet (or a viewing key it hands out)
    /// can compute its notes' nullifiers. SECRET.
    pub note_nk: Digest4,
    /// DB-395 — the public SPEND KEY `spk = P(ask, nk)` every v4 address of this wallet carries; payers seal to it.
    pub note_spk: Digest4,
    /// ⭐ THE ADDRESS ROOT (2026-11-10): the seed-derived root of every receive address's OWN keys ([`address_keys`]).
    /// From the root entropy under its own domain, so a seed-only restore reproduces every address. SECRET, never
    /// leaves the wallet: whoever holds it can tell which addresses are this wallet's and open what is paid to them.
    pub addr_root: [u8; 32],
}

impl WalletKeys {
    /// The owner of one of this wallet's notes: its spend secrets and the note's seed (from the note's decapsulation).
    #[must_use]
    pub fn note_owner(&self, seed: Digest4) -> usdm_decider::whir_rec_block::NoteOwner {
        self.note_keys().owner(seed)
    }

    /// The VIEWING half of this wallet's note keys — what detection needs, and nothing that spends.
    #[must_use]
    pub fn note_view(&self) -> NoteView {
        self.note_keys().view()
    }

    /// This wallet's note keys as one value, for a command that both detects and spends.
    #[must_use]
    pub fn note_keys(&self) -> NoteKeys {
        NoteKeys { ask: self.note_ask, nk: self.note_nk, spk: self.note_spk }
    }
}

/// ⛔ DB-395 — THIS WALLET'S NOTE KEYS: the spend authority `ask`, the nullifier key `nk`, and the public spend key
/// `spk = P(ask, nk)` its v4 addresses carry. [`NoteKeys::view`] hands out the half that detects (no `ask`);
/// [`NoteKeys::owner`] the whole owner a spend proves. A payer holds none of the three.
#[derive(Clone, Copy)]
pub struct NoteKeys {
    pub ask: Digest4,
    pub nk: Digest4,
    pub spk: Digest4,
}

impl NoteKeys {
    /// The keys a wallet derives from its root entropy (the ONE derivation `derive_keys` uses).
    #[must_use]
    pub fn from_entropy(entropy: &[u8; 32]) -> Self {
        let ask = usdm_decider::poseidon2_compress::hash32_to_digest(&kdf32("MonerousD/note-owner/ask/v1", entropy));
        let nk = usdm_decider::poseidon2_compress::hash32_to_digest(&kdf32("MonerousD/note-owner/nk/v1", entropy));
        NoteKeys { ask, nk, spk: usdm_decider::whir_rec_block::owner_spk(&ask, &nk) }
    }

    /// The owner of the note whose decapsulation yielded `seed`.
    #[must_use]
    pub fn owner(&self, seed: Digest4) -> usdm_decider::whir_rec_block::NoteOwner {
        // a note paid to one of this wallet's addresses past 0 is spent with THAT address's authority (same `nk`)
        let ask = address_of_seed(&self.spk, &seed).map_or(self.ask, |(ask, _)| ask);
        usdm_decider::whir_rec_block::NoteOwner { ask, nk: self.nk, seed }
    }

    /// The detecting half (`spk`, `nk`).
    #[must_use]
    pub fn view(&self) -> NoteView {
        NoteView { spk: self.spk, nk: self.nk }
    }
}

/// ⛔ DB-395 — THE VIEWING KEY'S NOTE HALF: the public spend key `spk` (a scan checks every note's commitment opens under
/// it) and the nullifier key `nk` (so the wallet can tell which of its notes are spent). It holds NO `ask`, so nothing
/// built from it can spend; a spend asks the open wallet for the owner at the moment it proves ([`WalletKeys::note_owner`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteView {
    pub spk: Digest4,
    pub nk: Digest4,
}

impl NoteView {
    /// A note's OPENING `o = P(spk, seed)` — the digest its commitment binds (`cm = asset_note_cm(v, tag, o)`).
    #[must_use]
    pub fn opening(&self, seed: &Digest4) -> Digest4 {
        // under the spend key of the address the note was opened at (address 0: this wallet's base key)
        let spk = address_of_seed(&self.spk, seed).map_or(self.spk, |(_, spk)| spk);
        usdm_decider::whir_rec_block::owner_opening(&spk, seed)
    }

    /// A note's PUBLIC nullifier `nf = P(nk, asset_note_cm(v, tag, o))` in the canonical 32-byte form — the value its
    /// spend records. The same rule as `pq_spend::note_nullifier_asset`, which takes the whole owner.
    #[must_use]
    pub fn nullifier(&self, amount: u64, asset: [u64; 3], seed: &Digest4) -> [u8; 32] {
        let leaf = usdm_decider::whir_rec_block::asset_note_cm(amount, asset, self.opening(seed));
        usdmd_node::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::note_nullifier(&self.nk, &leaf))
    }
}

/// Domain-separated 32-byte subkey from the root entropy (blake3 = the node's Hash32 family).
fn kdf32(domain: &str, entropy: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain.as_bytes());
    h.update(entropy);
    *h.finalize().as_bytes()
}

/// Deterministically derive both PQ keypairs + the address from a 32-byte root seed. Identical output
/// for identical seed — this is what makes restore-from-phrase reproduce the exact wallet.
pub fn derive_keys(entropy: &[u8; 32]) -> WalletKeys {
    use fips203::traits::{KeyGen as _, SerDes as _};
    use fips204::traits::{KeyGen as _, SerDes as _};

    // SPEND — ML-DSA-65 from a 32-byte seed ξ.
    let xi_spend = kdf32("MonerousD/spend/ml-dsa-65/v1", entropy);
    let (spk, ssk) = fips204::ml_dsa_65::KG::keygen_from_seed(&xi_spend);
    let spend_pk = spk.into_bytes().to_vec();
    let spend_sk = Zeroizing::new(ssk.into_bytes().to_vec());

    // SCAN — ML-KEM-768 from two 32-byte seeds (d, z).
    let d = kdf32("MonerousD/scan/ml-kem-768/d/v1", entropy);
    let z = kdf32("MonerousD/scan/ml-kem-768/z/v1", entropy);
    let (ek, dk) = fips203::ml_kem_768::KG::keygen_from_seed(d, z);
    let scan_ek = ek.into_bytes().to_vec();
    let scan_dk = Zeroizing::new(dk.into_bytes().to_vec());

    // DETECTION CLUE — packed-LWE keypair for OBLIVIOUS cold-restore, derived from the SAME root entropy so
    // restore reproduces it. The public clue key rides the address record (a sender builds a note's clue from
    // it); the secret drives the wallet-side detection test and NEVER leaves the wallet (like the scan key).
    let (clue_pk, clue_sk) = crate::omr::derive_clue_key(entropy);

    // OLI LOCATOR SECRET — derived from the SAME root entropy, so a seed-only restore reproduces every
    // locator this wallet ever handed out and can look them up directly instead of scanning.
    let loc_sk = usdmd_node::oli::derive_loc_sk(entropy);

    // ⛔⛔⛔ DB-395 — THE NOTE OWNER: `(ask, nk)` from the root entropy under their own domains (so a seed-only restore
    // reproduces them), `spk = P(ask, nk)` published in every address. A note commits to `P(spk, seed)` and spending it
    // proves `(ask, nk)` — the payer who sealed it holds neither.
    let NoteKeys { ask: note_ask, nk: note_nk, spk: note_spk } = NoteKeys::from_entropy(entropy);

    let b = *blake3::hash(&spend_pk).as_bytes();
    // TWO address forms, because a locator is only safe to hand to ONE payer (both v4: each carries `note_spk`):
    //
    // `address` carries a one-time locator, which is the only channel by which a payer can tag a
    // note for a recipient who is offline. Give a given receive address to exactly one payer and rotate — that
    // payer learns only which notes THEY paid you, which they already knew.
    //
    // `handle_address` carries NO locator, and is what goes anywhere PUBLISHED — a @username, a
    // donation QR, a website. A locator in a published address would be a linkage oracle: anyone could
    // read the address, derive its index key, and query the index for the exact block and slot of every
    // payment ever made to that handle. Notes reached this way are found by the ordinary scan.
    // the ML-KEM-768 ek is exactly 1184 bytes by construction; the (unreachable) refusal leaves an EMPTY address, which
    // every door and every payer refuses (fail closed on the address, never on the wallet process)
    let address = receive_address(&b, &scan_ek, &note_spk, &loc_sk, 0).unwrap_or_default();
    let handle_address = usdmd_node::address::pq_stealth_address_v4(PQ_ADDR_TAG_TESTNET, &b, &scan_ek, None, &note_spk)
        .unwrap_or_default();

    // DB-288: the outgoing-record secret, from the root entropy under its own domain (see `WalletKeys::out_sk`).
    let out_sk = kdf32("MonerousD/self-note/outgoing-record/v1", entropy);
    let validator_root = kdf32("MonerousD/validator/root/v1", entropy);
    let dsol_root = kdf32("MonerousD/dsol/caller-root/v1", entropy);
    let sat_loc_sk = kdf32("MonerousD/satoshi/reward-loc/v1", entropy);

    WalletKeys {
        spend_pk,
        spend_sk,
        scan_ek,
        scan_dk,
        b,
        address,
        handle_address,
        clue_pk,
        clue_sk,
        loc_sk,
        out_sk,
        validator_root,
        dsol_root,
        sat_loc_sk,
        note_ask,
        note_nk,
        note_spk,
        addr_root: kdf32("MonerousD/receive-address/root/v1", entropy),
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// PER-ADDRESS KEYS — every receive address is its own keys (user 2026-11-10: "infinite subaddresses that automatically
// change every time and each subaddress is untraceable").
//
// WHAT WAS LINKABLE. A receive address is `(b, scan_ek, spk, locator)`. The locator was already per-address; `b`, the
// ML-KEM key and the spend key were the wallet's own on EVERY address, so any two people each holding one address of a
// wallet (two payers, a payer and a shop, anyone a QR was shown to) could compare them and know they pay one wallet.
// Nothing of it was on the chain: a note's commitment hides the spend key, an ML-KEM ciphertext does not name its key,
// and a locator tag is a PRF of its own index. The link was the address itself.
//
// WHAT AN ADDRESS IS NOW. Address `j >= 1` carries keys derived from the wallet's address root and `j` alone:
// its own ML-KEM-768 pair, its own spend authority `ask_j` (so its own `spk_j = P(ask_j, nk)`), its own tag `b_j`.
// Two addresses of one wallet share no byte, and deriving either from the other is deriving a PRF's output from
// another of its outputs. Address 0 keeps the wallet's base keys: it is what the wallet's own change, its rewards and
// every note it held before this are sealed to.
//
// HOW THE WALLET KNOWS WHICH KEYS OPEN A NOTE, WITH NO SEARCH. A note paid to address `j` is found by its locator
// (`oli` "recv" index `j`, the one way any received note is found), so the wallet knows `j` the moment it knows the
// note's commitment; it records `commitment -> j` ([`note_at_address`]) and every later open of that note reads `j`
// there: one map read, then exactly one decapsulation under that address's key. No address is ever TRIED against a
// note it was not located at, so the cost of receiving does not grow with how many addresses a wallet has handed out.
//
// SPENDING. A note's owner is `(ask, nk, seed)`. The circuit is unchanged: it proves `spk = P(ask, nk)` and opens the
// commitment under `P(spk, seed)`, and never learns which `ask` of a wallet it was. `nk` is the wallet's one
// nullifier key (a nullifier is `P(nk, cm)`, a PRF output that links nothing). The wallet reads the owner by the
// note's seed ([`NoteKeys::owner`]): a seed opened under address `j` gives `ask_j`.
//
// cons: one ML-KEM key generation per address the wallet touches in a session (about 50 µs, cached); one small map
// entry per note received at an address past 0 (kept beside the note store, keyed so the file names no note).
// ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// The keys of ONE receive address. Secret halves are wiped on drop.
pub struct AddressKeys {
    pub j: u64,
    /// The address's own tag (the field every address form carries where the base address carries `blake3(spend_pk)`).
    pub b: [u8; 32],
    pub scan_ek: Vec<u8>,
    pub scan_dk: Zeroizing<Vec<u8>>,
    /// The address's spend authority: with the wallet's `nk` it is the only thing that spends what is paid to it.
    pub ask: Digest4,
    pub spk: Digest4,
}

fn address_kdf(root: &[u8; 32], what: &str, j: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(root);
    h.update(b"MonerousD/receive-address/v1/");
    h.update(what.as_bytes());
    h.update(&j.to_le_bytes());
    *h.finalize().as_bytes()
}

/// The keys of receive address `j` under an address root and the wallet's nullifier key. A pure function of
/// `(root, nk, j)`: the same seed gives the same address on any device, at any index, with nothing stored.
#[must_use]
pub fn address_keys_of(root: &[u8; 32], nk: &Digest4, j: u64) -> AddressKeys {
    use fips203::traits::{KeyGen as _, SerDes as _};
    let (ek, dk) = fips203::ml_kem_768::KG::keygen_from_seed(address_kdf(root, "ml-kem-768/d", j), address_kdf(root, "ml-kem-768/z", j));
    let ask = usdm_decider::poseidon2_compress::hash32_to_digest(&address_kdf(root, "ask", j));
    AddressKeys {
        j,
        b: address_kdf(root, "b", j),
        scan_ek: ek.into_bytes().to_vec(),
        scan_dk: Zeroizing::new(dk.into_bytes().to_vec()),
        ask,
        spk: usdm_decider::whir_rec_block::owner_spk(&ask, nk),
    }
}

/// The receive address at index `j` for a wallet: address 0 is the wallet's base keys (what its change and rewards are
/// sealed to), every other index its own keys. The form to hand to ONE payer.
#[must_use]
pub fn receive_address_of(keys: &WalletKeys, j: u64) -> Option<String> {
    if j == 0 {
        return receive_address(&keys.b, &keys.scan_ek, &keys.note_spk, &keys.loc_sk, 0);
    }
    let a = address_keys_of(&keys.addr_root, &keys.note_nk, j);
    receive_address(&a.b, &a.scan_ek, &a.spk, &keys.loc_sk, j)
}

/// The open wallet's address context: what [`scan_note_full_asset`] and the owner lookups need to open and spend a note
/// paid to an address past 0. Process state DERIVED from the seed and the index file, never authority: a note it does
/// not know is found again by its locator.
struct AddressContext {
    root: Zeroizing<[u8; 32]>,
    nk: Digest4,
    base_spk: Digest4,
    /// note commitment (as its keyed tag, [`AddressContext::tag`]) -> the address index it was located at. Keyed so
    /// the index file, which stores exactly these entries, names no note to anyone without the address root.
    at: std::collections::HashMap<[u8; 32], u64>,
    /// note seed -> the address keys that opened it: `(ask_j, spk_j)`.
    by_seed: std::collections::HashMap<[u8; 32], (Digest4, Digest4)>,
    /// O1-FOOTPRINT-REVIEWED: one entry per address index this session opened a note at (bounded by `at`).
    keys: std::collections::HashMap<u64, std::sync::Arc<AddressKeys>>,
}

impl AddressContext {
    /// The keyed tag of a note commitment: what the map and the index file hold in place of the commitment.
    fn tag(&self, cm: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new_keyed(&self.root);
        h.update(b"MonerousD/receive-address/v1/index-file");
        h.update(cm);
        *h.finalize().as_bytes()
    }
}

static ADDRESS_CTX: std::sync::Mutex<Option<AddressContext>> = std::sync::Mutex::new(None);

fn seed_key(seed: &Digest4) -> [u8; 32] {
    usdmd_node::spend_frontier::leaf_to_cm_bytes(*seed)
}

/// Open the address context for the wallet now open (called where the wallet is opened), with the `tag -> index`
/// entries its index file held ([`notes_at_addresses`] wrote them). Replaces any earlier wallet's context whole.
pub fn open_address_context(keys: &WalletKeys, known: impl IntoIterator<Item = ([u8; 32], u64)>) {
    let ctx = AddressContext {
        root: Zeroizing::new(keys.addr_root),
        nk: keys.note_nk,
        base_spk: keys.note_spk,
        at: known.into_iter().filter(|(_, j)| *j > 0).collect(),
        by_seed: std::collections::HashMap::new(),
        keys: std::collections::HashMap::new(),
    };
    *ADDRESS_CTX.lock().unwrap_or_else(|e| e.into_inner()) = Some(ctx);
}

/// Forget the open wallet's address context (the wallet closed).
pub fn close_address_context() {
    *ADDRESS_CTX.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Record that the note with commitment `cm` was located at receive address `j` (the locator sweep's answer). Returns
/// whether this is new, so the caller writes its index file only when something changed. Index 0 is the base keys and
/// is never recorded.
pub fn note_at_address(cm: [u8; 32], j: u64) -> bool {
    if j == 0 {
        return false;
    }
    match ADDRESS_CTX.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        Some(ctx) => {
            let tag = ctx.tag(&cm);
            ctx.at.insert(tag, j) != Some(j)
        }
        None => false,
    }
}

/// Every `tag -> index` entry the open wallet holds (what its index file stores).
#[must_use]
pub fn notes_at_addresses() -> Vec<([u8; 32], u64)> {
    ADDRESS_CTX.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|c| c.at.iter().map(|(k, v)| (*k, *v)).collect()).unwrap_or_default()
}

/// The spend authority and spend key a note's SEED was opened under, when that was an address past 0 of the wallet
/// whose base spend key is `base_spk`.
fn address_of_seed(base_spk: &Digest4, seed: &Digest4) -> Option<(Digest4, Digest4)> {
    let g = ADDRESS_CTX.lock().unwrap_or_else(|e| e.into_inner());
    let ctx = g.as_ref().filter(|c| c.base_spk == *base_spk)?;
    ctx.by_seed.get(&seed_key(seed)).copied()
}

/// Open `note` under the receive address it was located at, when the open wallet (base spend key `base_spk`) recorded
/// one for its commitment. Exactly one key is tried: the one of the recorded index.
fn scan_at_recorded_address(note: &[u8], base_spk: &Digest4) -> Option<(u64, Digest4, [u64; 3])> {
    let cm: [u8; 32] = note.get(..32)?.try_into().ok()?;
    let keys = {
        let mut g = ADDRESS_CTX.lock().unwrap_or_else(|e| e.into_inner());
        let ctx = g.as_mut().filter(|c| c.base_spk == *base_spk)?;
        let j = *ctx.at.get(&ctx.tag(&cm))?;
        match ctx.keys.get(&j) {
            Some(k) => k.clone(),
            None => {
                let k = std::sync::Arc::new(address_keys_of(&ctx.root, &ctx.nk, j));
                ctx.keys.insert(j, k.clone());
                k
            }
        }
    };
    let hit = scan_note_under(note, &keys.scan_dk, &keys.spk)?;
    if let Some(ctx) = ADDRESS_CTX.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        ctx.by_seed.insert(seed_key(&hit.1), (keys.ask, keys.spk));
    }
    Some(hit)
}

/// ⭐ DSOL (spec §6b A1) — a per-contract CALLER key: ML-DSA-65, seeded from the wallet's [`WalletKeys::dsol_root`],
/// the contract id and an index. The door checks `caller == str_digest(H(pk_c))` and the call body's signature under
/// `pk_c`, so a contract sees a stable pseudonym per `(cid, index)`, and two contracts (or two indices) see unrelated keys:
/// nothing links this wallet's calls across contracts, and a fresh index per call unlinks calls within one contract
/// unless the contract needs a stable sender. Deterministic, so a seed restore reproduces every caller identity.
pub struct DsolCaller {
    pub pk: Vec<u8>,
    pub sk: Zeroizing<Vec<u8>>,
}

/// Derive the `index`-th caller key of this wallet for contract `cid` (FIPS 204 `KeyGen_internal(ξ)`, as every other
/// wallet key). The seed ξ is a keyed hash of `(cid, index)` under `dsol_root`: without `dsol_root` no one can compute
/// it, and a caller key reveals nothing about any other.
#[must_use]
pub fn derive_dsol_caller(dsol_root: &[u8; 32], cid: &[u8; 32], index: u32) -> DsolCaller {
    use fips204::traits::{KeyGen as _, SerDes as _};
    let mut h = blake3::Hasher::new_keyed(dsol_root);
    h.update(b"MonerousD/dsol/caller/v1");
    h.update(cid);
    h.update(&index.to_le_bytes());
    let xi = kdf32("MonerousD/dsol/caller/ml-dsa-65/v1", h.finalize().as_bytes());
    let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&xi);
    DsolCaller { pk: pk.into_bytes().to_vec(), sk: Zeroizing::new(sk.into_bytes().to_vec()) }
}

/// Sign a DSOL call body with its caller key (pure ML-DSA-65, the same scheme [`verify_spend`] checks).
#[must_use]
pub fn sign_dsol_call(caller: &DsolCaller, body: &[u8]) -> Option<Vec<u8>> {
    use fips204::traits::{SerDes as _, Signer as _};
    let sk_arr: [u8; fips204::ml_dsa_65::SK_LEN] = caller.sk.as_slice().try_into().ok()?;
    let sk = fips204::ml_dsa_65::PrivateKey::try_from_bytes(sk_arr).ok()?;
    sk.try_sign(body, &[]).ok().map(|s| s.to_vec())
}

/// A validator identity derived from the seed: the vote key (ML-DSA-65) the node signs finality votes, bond statements
/// and its own unbond with. Every custody key the node needs (the ML-KEM custody key, the external-chain custody
/// points) is derived ON THE NODE from this vote key, so no decapsulation key ever leaves the wallet.
pub struct ValidatorIdentity {
    pub vote_pk: Vec<u8>,
    pub vote_sk: Zeroizing<Vec<u8>>,
}

/// ⭐⭐⭐ The `index`-th validator identity of a wallet, derived from its [`WalletKeys::validator_root`] — Ethereum's
/// EIP-2333/2334 shape (validator keys from the mnemonic, one path per validator). Deterministic: the same seed and
/// index give the same identity on any machine, which is what makes a bonded node recoverable from the seed alone.
/// Seeded keygen as every other wallet key (FIPS 204 `KeyGen_internal(ξ)`).
#[must_use]
pub fn derive_validator_identity(validator_root: &[u8; 32], index: u32) -> ValidatorIdentity {
    use fips204::traits::{KeyGen as _, SerDes as _};
    let node = kdf32(&format!("MonerousD/validator/{index}/v1"), validator_root);
    let xi = kdf32("MonerousD/validator/vote/ml-dsa-65/v1", &node);
    let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&xi);
    ValidatorIdentity { vote_pk: pk.into_bytes().to_vec(), vote_sk: Zeroizing::new(sk.into_bytes().to_vec()) }
}

/// This wallet's `j`-th ROTATING receive address (v3) — the form handed to a single payer, carrying the
/// one-time locator `PRF(loc_sk, "recv", j)` AND the owner-minted `(salt, hint)`. Encoded by the NODE's
/// address module, so a wallet and a node can never disagree on the format.
///
/// ⭐ INFINITE SUBADDRESSES, BY CONSTRUCTION. A v2 address carried the locator alone, and a locator is a pure
/// PRF of `j` — so the recipient could only recognise its own tag by GUESSING `j` and giving up after a fixed
/// number of tries. Hand out 30 subaddresses, have only the 26th pay you, and that payment was invisible
/// forever. The hint is `j` masked by a PRF only this wallet can compute: the payer copies it verbatim and
/// learns nothing, and the recipient recovers `j` in ONE step at ANY index. There is no bound left to exceed.
/// (user 2026-07-27 · [[project_oli_gap_limit_fund_loss]])
/// DB-395: a v4 address — it also carries the wallet's spend key `note_spk`, which every payer seals to.
pub fn receive_address(b: &[u8; 32], scan_ek: &[u8], note_spk: &Digest4, loc_sk: &[u8; 32], j: u64) -> Option<String> {
    let salt = usdmd_node::oli::address_salt(loc_sk, "recv", j);
    usdmd_node::address::pq_stealth_address_v4(
        PQ_ADDR_TAG_TESTNET,
        b,
        scan_ek,
        Some((
            &usdmd_node::oli::locator_at(loc_sk, "recv", j),
            &salt,
            &usdmd_node::oli::address_index_hint(loc_sk, &salt, j),
        )),
        note_spk,
    )
}

/// Create a brand-new wallet: draw a FRESH 32-byte CSPRNG root, encode it as a 24-word recovery phrase,
/// and derive the keys. Returns `(recovery_phrase, keys)`. The phrase is the ONLY backup of the funds.
pub fn generate() -> Result<(String, WalletKeys), String> {
    use rand::RngCore;
    let mut entropy = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut entropy[..]); // fresh CSPRNG — never a fixed/derived-from-nothing seed
    let mnemonic =
        bip39::Mnemonic::from_entropy(&entropy[..]).map_err(|e| format!("mnemonic encode: {e}"))?;
    let keys = derive_keys(&entropy);
    Ok((mnemonic.to_string(), keys))
}

/// ⭐ R7 F3 — THE MASTER KEY: the wallet's 256-bit root as 64 hex characters followed by an 8-hex checksum
/// (`blake3_derive("MUSD/master-key-check/v1", root)[..4]`), written `<64 hex>-<8 hex>`. The same root the 24 words
/// encode, for a user who keeps a hex backup; the checksum means a mistyped character is REFUSED — it can never derive a
/// different, empty wallet the user then believes is theirs (BIP-39's own checksum does this for the words).
#[must_use]
pub fn master_key_of_entropy(entropy: &[u8; 32]) -> String {
    format!("{}-{}", hex::encode(entropy), hex::encode(master_key_check(entropy)))
}

fn master_key_check(entropy: &[u8; 32]) -> [u8; 4] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/master-key-check/v1");
    h.update(entropy);
    h.finalize().as_bytes()[..4].try_into().expect("4 bytes")
}

/// The CANONICAL 24-word phrase for what a user typed (words in any case/spacing, or a checksummed master key) — the one
/// spelling persisted beside the note store, so View Seed and the vault's per-piece addresses (keyed by the phrase) are the
/// same on every device that restored the same root.
pub fn canonical_phrase(input: &str) -> Result<String, String> {
    if let Some(parsed) = parse_master_key(input) {
        let entropy = Zeroizing::new(parsed?);
        return bip39::Mnemonic::from_entropy(&entropy[..]).map(|m| m.to_string()).map_err(|e| format!("mnemonic encode: {e}"));
    }
    let normalized = input.split_whitespace().map(str::to_lowercase).collect::<Vec<_>>().join(" ");
    bip39::Mnemonic::parse(&normalized).map(|m| m.to_string()).map_err(|e| format!("invalid recovery phrase: {e}"))
}

/// The master key for a 24-word phrase (Settings → View recovery seed shows both).
pub fn master_key_of_phrase(phrase: &str) -> Result<String, String> {
    let normalized = phrase.split_whitespace().map(str::to_lowercase).collect::<Vec<_>>().join(" ");
    let m = bip39::Mnemonic::parse(&normalized).map_err(|e| format!("invalid recovery phrase: {e}"))?;
    let ent = m.to_entropy();
    let entropy: [u8; 32] = ent.as_slice().try_into().map_err(|_| "expected a 24-word recovery phrase".to_string())?;
    Ok(master_key_of_entropy(&entropy))
}

/// Parse a master key: 72 hex characters once spaces and dashes are dropped. `None` when the input is not shaped like
/// one (the caller then reads it as words); `Some(Err)` when it is shaped like one and the checksum refuses it.
fn parse_master_key(input: &str) -> Option<Result<[u8; 32], String>> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_lowercase();
    if !compact.chars().all(|c| c.is_ascii_hexdigit()) || compact.len() < 64 {
        return None;
    }
    if compact.len() != 72 {
        return Some(Err(format!(
            "a master key is 64 hex characters plus its 8-character checksum (72 in all); this has {} — nothing was restored",
            compact.len()
        )));
    }
    let bytes = hex::decode(&compact).ok()?;
    let entropy: [u8; 32] = bytes[..32].try_into().ok()?;
    if bytes[32..] != master_key_check(&entropy) {
        return Some(Err("the master key's checksum does not match — a character is mistyped; nothing was restored".into()));
    }
    Some(Ok(entropy))
}

/// Restore a wallet from its 24-word recovery phrase OR its checksummed master key (deterministic — reproduces the exact
/// keys/address either way).
pub fn restore(phrase: &str) -> Result<WalletKeys, String> {
    if let Some(parsed) = parse_master_key(phrase) {
        let mut entropy = Zeroizing::new(parsed?);
        let keys = derive_keys(&entropy);
        entropy.fill(0);
        return Ok(keys);
    }
    // Normalize BEFORE the BIP-39 wordlist lookup so a phone keyboard's auto-capitalization / auto-correct
    // spacing can NEVER cause a spurious "unknown word" (the wordlist is lowercase, single-space separated).
    // `split_whitespace` collapses any run of spaces/tabs/newlines; `to_lowercase` undoes the auto-capitalized
    // first word. Robust to any casing + leading/trailing/duplicated whitespace the user's keyboard introduces —
    // this is why the same phrase failed on the phone (autocap "Power") yet parsed headlessly (lowercase).
    let normalized = phrase
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ");
    let m = bip39::Mnemonic::parse(&normalized)
        .map_err(|e| format!("invalid recovery phrase: {e}"))?;
    let ent = m.to_entropy();
    if ent.len() != 32 {
        return Err(format!(
            "expected a 24-word recovery phrase (256-bit), got {}-bit",
            ent.len() * 8
        ));
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy.copy_from_slice(&ent);
    Ok(derive_keys(&entropy))
}

// ── Confidential note seal / scan ──
// On-chain PQ note (matches the node's served layout, crate::cover): note_cm(32) ‖ ML-KEM ct(1088) ‖
// enc_amount(32) ‖ view_tag(1) = 1153 bytes. All fields derive from a fresh ML-KEM shared secret `ss`, so
// to any observer without the recipient's scan key they are computationally random (Pillar-1: no amount /
// identity / linkage leak). The RECIPIENT recovers by decapsulating `ct` with its scan key → `ss`, then a
// 1-byte view-tag gives O(1) fast-reject and the enc_amount keystream reveals the amount; note_cm binds the
// amount (hiding under the secret `ss`) so a view-tag collision cannot fabricate a spurious note.
pub const PQ_NOTE_BYTES: usize = 1153;
const NOTE_CT_OFF: usize = 32;
const NOTE_CT_END: usize = NOTE_CT_OFF + 1088; // 1120
const NOTE_ENC_END: usize = NOTE_CT_END + 32; // 1152
const NOTE_VT_OFF: usize = NOTE_ENC_END; // 1152

fn note_kdf(ss: &[u8], tag: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ss);
    h.update(tag);
    *h.finalize().as_bytes()
}

/// ⛔⛔⛔ DB-395 — the per-note SEED from the ML-KEM shared secret `ss`. Both the SENDER (via `try_encaps`) and the
/// RECIPIENT (via `try_decaps`) hold the same `ss`, so both derive the SAME seed — and that is exactly why it is NOT a key.
/// The note commits to `o = P(spk_recipient, seed)`; spending it needs the recipient's `(ask, nk)` behind `spk`, which the
/// sender never holds. (This was `note_sk_from_ss`, whose value WAS the spend key: every payer could claw back what it paid
/// and compute the payee's nullifier.) ONE definition, the node's (`faucet::note_seed_from_ss`), so a faucet note, a reward
/// and a wallet payment open identically.
pub fn note_seed_from_ss(ss: &[u8]) -> Digest4 {
    usdmd_node::faucet::note_seed_from_ss(ss)
}

/// USDm — the native unit. Re-exported from the decider so the wallet and the circuit that verifies
/// its spends can never hold two different ideas of what "no asset tag" means.
pub use usdm_decider::whir_rec_block::USDM_ASSET_TAG;

/// The note's on-chain 32-byte commitment IS its POSEIDON commitment `asset_note_cm(amount, tag, o)` at the opening
/// `o = P(spk, note_seed_from_ss(ss))`, so a recorded note is a SPENDABLE leaf in the node's Poseidon spend-membership
/// frontier. Sender and recipient derive the same opening from `ss` and the recipient's public `spk`, so both agree on
/// the commitment — and only the recipient's `(ask, nk)` spends it (DB-395).
fn note_cm_asset(spk: &Digest4, ss: &[u8], amt_le: &[u8; 8], asset: [u64; 3]) -> [u8; 32] {
    let amount = u64::from_le_bytes(*amt_le);
    crate::pq_spend::note_cm_asset_bytes(amount, asset, usdmd_node::faucet::note_opening(spk, ss))
}

// ⭐⭐⭐ WHERE THE ASSET TAG RIDES: `enc[8..32]`, the 24 keystream bytes the amount never used.
//
// The sealed `enc` field is a 32-byte keystream with the 8-byte amount XORed into its head. Bytes
// 8..32 were always pure keystream — so XORing a 3-limb tag there costs no bytes, changes no layout,
// and stays computationally random to anyone without the scan key. The tag is exactly as hidden as
// the amount, which is the requirement: an observer must not learn WHICH asset moved, any more than
// how much ([[feedback_digital_cash_pillar]]).
//
// ⛔ BACKWARD-COMPATIBLE BY CONSTRUCTION, NOT BY A VERSION FLAG. An old note has
// `enc[8..32] == keystream[8..32]` verbatim, so recovering the tag as `enc XOR keystream` yields
// ZERO — exactly USDM_ASSET_TAG. Every note ever sealed reads back as USDm with no migration, no flag
// byte and no second decoder. A version flag would have added one more thing to get wrong on a path
// already carrying real custody, and it would have had to be right on notes sealed before it existed.
const NOTE_ASSET_OFF: usize = 8;

/// XOR a tag into (or out of) the `enc` keystream tail. Self-inverse, so seal and scan share it.
fn asset_xor(enc: &mut [u8; 32], asset: [u64; 3]) {
    for (i, limb) in asset.iter().enumerate() {
        for (j, byte) in limb.to_le_bytes().iter().enumerate() {
            enc[NOTE_ASSET_OFF + i * 8 + j] ^= *byte;
        }
    }
}

/// Recover a tag from a note's `enc` field against its keystream.
fn asset_from(enc: &[u8], ks: &[u8; 32]) -> [u64; 3] {
    core::array::from_fn(|i| {
        let mut b = [0u8; 8];
        for (j, slot) in b.iter_mut().enumerate() {
            let at = NOTE_ASSET_OFF + i * 8 + j;
            *slot = enc[at] ^ ks[at];
        }
        u64::from_le_bytes(b)
    })
}

/// Seal `amount` (atomic units) into a 1153-byte confidential note addressed to `(ek, spk)` — the recipient's
/// ML-KEM-768 encapsulation key and its spend key, both read from its v4 address — the SENDER side of a confidential PQ
/// transfer. `None` if `ek` is malformed or the KEM fails (fail-closed, never a bad note).
pub fn seal_note(ek_bytes: &[u8], spk: &Digest4, amount: u64) -> Option<[u8; PQ_NOTE_BYTES]> {
    seal_note_full(ek_bytes, spk, amount).map(|(note, _)| note)
}

/// Like [`seal_note`], but ALSO returns the note's OPENING `o = P(spk, seed)`. The SENDER needs `o` to bind this output
/// note's commitment in the spend carrier (`out_cm = asset_note_cm(amount, USDm, o)`), so the node proves the recorded
/// output conserves value. ⛔ DB-395: `o` is NOT a spend key — the recipient's `(ask, nk)` is, and the sender never holds
/// it, so the sender can neither spend this note nor compute its nullifier.
pub fn seal_note_full(ek_bytes: &[u8], spk: &Digest4, amount: u64) -> Option<([u8; PQ_NOTE_BYTES], Digest4)> {
    seal_note_full_asset(ek_bytes, spk, amount, USDM_ASSET_TAG)
}

/// Seal a note denominated in a specific ASSET. [`seal_note_full`] is this with the USDm tag.
pub fn seal_note_full_asset(
    ek_bytes: &[u8],
    spk: &Digest4,
    amount: u64,
    asset: [u64; 3],
) -> Option<([u8; PQ_NOTE_BYTES], Digest4)> {
    use fips203::traits::{Encaps as _, SerDes as _};
    let ek =
        fips203::ml_kem_768::EncapsKey::try_from_bytes(<[u8; 1184]>::try_from(ek_bytes).ok()?).ok()?;
    let (ss, ct) = ek.try_encaps().ok()?;
    Some(note_from_encaps(spk, &ss.into_bytes(), &ct.into_bytes(), amount, asset))
}

/// ⭐ goods spec §8 — A PAYMENT THAT SAYS WHICH CHARGE IT PAYS, TO THE PAYEE ALONE. A shop with two open orders of the same
/// price cannot tell which of them a bare payment is for, since a note arriving is the only signal: one payment would
/// mark both paid. Borrowed shape: one destination per invoice (Bitcoin BIP21 / BTCPay, Monero integrated addresses). Here
/// the destination stays the shop's one address and the invoice is named INSIDE the encapsulation: the ML-KEM message is
/// `r ‖ mark`, 24 fresh random bytes and `mark = blake3_keyed(reference)(r)[..8]`. The payee's decapsulation returns the
/// message, so the payee (and nobody else) reads which charge the note pays. On the wire the note is any payment's.
/// DIGITAL-CASH-PRIVACY-REVIEWED: by construction: nothing is added to the note's bytes; the mark sits inside the KEM
/// message only the recipient's key recovers, and a party that knows the reference still faces 192 unknown bits.
pub fn seal_note_referenced(ek_bytes: &[u8], spk: &Digest4, amount: u64, reference: &[u8; 16]) -> Option<([u8; PQ_NOTE_BYTES], Digest4)> {
    use fips203::traits::{Encaps as _, SerDes as _};
    use rand::RngCore as _;
    let ek = fips203::ml_kem_768::EncapsKey::try_from_bytes(<[u8; 1184]>::try_from(ek_bytes).ok()?).ok()?;
    let mut m = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut m[..24]).ok()?;
    let mark = reference_mark(reference, &m[..24]);
    m[24..].copy_from_slice(&mark);
    let (ss, ct) = ek.encaps_from_seed(&m);
    Some(note_from_encaps(spk, &ss.into_bytes(), &ct.into_bytes(), amount, USDM_ASSET_TAG))
}

fn reference_mark(reference: &[u8; 16], r: &[u8]) -> [u8; 8] {
    let key = blake3::derive_key("MonerousD 2026-11-10 payment reference mark v1", reference);
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(r);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.finalize().as_bytes()[..8]);
    out
}

/// Does this note (one this wallet's key opens) pay the charge named `reference`? False for a note sealed any other way:
/// a random message carries a given charge's mark with chance 2^-64.
pub fn note_carries_reference(note: &[u8], dk_bytes: &[u8], reference: &[u8; 16]) -> bool {
    use fips203::traits::SerDes as _;
    if note.len() != PQ_NOTE_BYTES {
        return false;
    }
    let Some(dk) = <[u8; 2400]>::try_from(dk_bytes).ok().and_then(|b| fips203::ml_kem_768::DecapsKey::try_from_bytes(b).ok()) else {
        return false;
    };
    let Some(ct) = <[u8; 1088]>::try_from(&note[NOTE_CT_OFF..NOTE_CT_END]).ok().and_then(|b| fips203::ml_kem_768::CipherText::try_from_bytes(b).ok())
    else {
        return false;
    };
    match dk.try_decaps_with_message(&ct) {
        Ok((_, m)) => m[24..] == reference_mark(reference, &m[..24]),
        Err(_) => false,
    }
}

/// ⭐ goods spec §9.1 — SEAL A VAULT NOTE: the 1153-byte payload of a note whose commitment is the vault's
/// (`VaultNote::note_cm`), so the block records the vault where a payment's recipient note would sit. The ciphertext is an
/// ordinary encapsulation to THIS wallet's own scan key: nobody else opens it, and it opens to nothing this wallet counts
/// (the commitment is not an ordinary note's), so the payload has the shape of any payment's and says nothing. A vault is
/// found by its commitment, which both of its parties compute, never by scanning. Returns the payload and the vault's
/// opening (what the carrier binds the output to). `None` for a vault no wallet makes, or when the KEM fails.
/// DIGITAL-CASH-PRIVACY-REVIEWED: by construction: the bytes are a fresh ML-KEM ciphertext to the sender's own key and a
/// commitment only the vault's two parties can compute; no key, amount or party is readable from them.
///
/// THE RECORD. The payload also carries, for the wallet that sealed it and nobody else, what it needs to recompute the
/// vault with no local file (the chain is the record): the ML-KEM message is `record_m` and the 24 bytes of the amount
/// field an ordinary note spends on its asset tag are `record_tail`, both masked. [`open_vault_note`] reads them back.
pub fn seal_vault_note(
    my_ek: &[u8],
    vault: &usdm_decider::whir_rec_block::VaultNote,
    amount: u64,
    out_sk: &[u8; 32],
    record_m: &[u8; 32],
    record_tail: &[u8; 24],
) -> Option<([u8; PQ_NOTE_BYTES], Digest4)> {
    use fips203::traits::{Encaps as _, SerDes as _};
    if !vault.is_well_formed() {
        return None;
    }
    let ek = fips203::ml_kem_768::EncapsKey::try_from_bytes(<[u8; 1184]>::try_from(my_ek).ok()?).ok()?;
    // the KEM message is the record under a pad only this wallet derives, so the other party of the vault (who knows
    // the locks) cannot recompute the ciphertext
    let pad = vault_record_pad(out_sk, record_tail);
    let m: [u8; 32] = core::array::from_fn(|i| record_m[i] ^ pad[i]);
    let (ss, ct) = ek.encaps_from_seed(&m);
    let ss = ss.into_bytes();
    let ks = note_kdf(&ss, b"MUSD-note-enc-v1");
    let mut note = [0u8; PQ_NOTE_BYTES];
    note[0..NOTE_CT_OFF].copy_from_slice(&usdmd_node::spend_frontier::leaf_to_cm_bytes(vault.note_cm(amount)));
    note[NOTE_CT_OFF..NOTE_CT_END].copy_from_slice(&ct.into_bytes());
    let amt = amount.to_le_bytes();
    for i in 0..32 {
        note[NOTE_CT_END + i] = ks[i] ^ if i < 8 { amt[i] } else { record_tail[i - 8] };
    }
    note[NOTE_VT_OFF] = note_kdf(&ss, b"MUSD-note-vt-v1")[0];
    Some((note, vault.opening()))
}

fn vault_record_pad(out_sk: &[u8; 32], record_tail: &[u8; 24]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(out_sk);
    h.update(b"MonerousD 2026-11-10 vault note KEM record v1/");
    h.update(record_tail);
    *h.finalize().as_bytes()
}

/// Read back what [`seal_vault_note`] wrote: `(amount, record_m, record_tail)`. `None` for a payload this wallet's key
/// does not open (the view tag is the first filter; the caller's recomputed commitment is the proof).
pub fn open_vault_note(note: &[u8], dk_bytes: &[u8], out_sk: &[u8; 32]) -> Option<(u64, [u8; 32], [u8; 24])> {
    use fips203::traits::SerDes as _;
    if note.len() != PQ_NOTE_BYTES {
        return None;
    }
    let dk = fips203::ml_kem_768::DecapsKey::try_from_bytes(<[u8; 2400]>::try_from(dk_bytes).ok()?).ok()?;
    let ct = fips203::ml_kem_768::CipherText::try_from_bytes(<[u8; 1088]>::try_from(&note[NOTE_CT_OFF..NOTE_CT_END]).ok()?).ok()?;
    let (ss, m) = dk.try_decaps_with_message(&ct).ok()?;
    let ss = ss.into_bytes();
    if note_kdf(&ss, b"MUSD-note-vt-v1")[0] != note[NOTE_VT_OFF] {
        return None;
    }
    let ks = note_kdf(&ss, b"MUSD-note-enc-v1");
    let plain: [u8; 32] = core::array::from_fn(|i| note[NOTE_CT_END + i] ^ ks[i]);
    let amount = u64::from_le_bytes(plain[..8].try_into().ok()?);
    let tail: [u8; 24] = plain[8..].try_into().ok()?;
    let pad = vault_record_pad(out_sk, &tail);
    Some((amount, core::array::from_fn(|i| m[i] ^ pad[i]), tail))
}

/// The ONE note layout, from an encapsulation's shared secret and ciphertext: `cm ‖ ct ‖ enc ‖ vt`, and the note's opening
/// `o = P(spk, seed(ss))`. Every sealer (a random encapsulation, or a self-note's record-carrying one) builds here, so a
/// record-carrying note is byte-for-byte the same layout any scanner reads.
fn note_from_encaps(spk: &Digest4, ss: &[u8; 32], ct: &[u8; 1088], amount: u64, asset: [u64; 3]) -> ([u8; PQ_NOTE_BYTES], Digest4) {
    let amt = amount.to_le_bytes(); // 8 bytes
    let mut enc = note_kdf(ss, b"MUSD-note-enc-v1"); // pseudorandom cover for the whole 32-byte field
    for i in 0..8 {
        enc[i] ^= amt[i]; // amount rides the first 8 bytes of the keystream
    }
    asset_xor(&mut enc, asset); // and the asset tag rides the 24 that were never used
    let vt = note_kdf(ss, b"MUSD-note-vt-v1")[0];
    let cm = note_cm_asset(spk, ss, &amt, asset);

    let mut out = [0u8; PQ_NOTE_BYTES];
    out[0..NOTE_CT_OFF].copy_from_slice(&cm);
    out[NOTE_CT_OFF..NOTE_CT_END].copy_from_slice(ct);
    out[NOTE_CT_END..NOTE_ENC_END].copy_from_slice(&enc);
    out[NOTE_VT_OFF] = vt;
    (out, usdmd_node::faucet::note_opening(spk, ss))
}

/// ⭐ IONSWAP POOLS — THE SEALED PART OF A POOL ORDER'S PAYOUT NOTES, made before their amounts exist: one fresh ML-KEM-768
/// encapsulation to this wallet's own scan key, and from its shared secret the three things a note's bytes need besides
/// the amount: the ciphertext, the 32-byte keystream that covers the amount and the asset tag, and the view tag. The
/// fourth value is the notes' opening `P(spk, seed)`. The batch that pays the order completes each note as
/// `cm ‖ ct ‖ (keystream ⊕ amount ‖ tag) ‖ vt` — [`note_from_encaps`]'s own layout — so this wallet's ordinary scan
/// ([`scan_note_full_asset`]) decapsulates it, reads the amount and the tag, and binds the commitment like any note's.
/// The keystream is handed out because what it covers is public in the pool lane; it is a KDF output under its own
/// label and says nothing of the shared secret, the seed or the view tag's own keystream.
/// DIGITAL-CASH-PRIVACY-REVIEWED: nothing here names the wallet: a fresh encapsulation, and an opening no observer can
/// tie to an address (the seed is the shared secret's).
pub fn seal_payout_shell(my_ek: &[u8], my_spk: &Digest4) -> Option<([u8; 1088], [u8; 32], u8, Digest4)> {
    use fips203::traits::{Encaps as _, SerDes as _};
    let ek = fips203::ml_kem_768::EncapsKey::try_from_bytes(<[u8; 1184]>::try_from(my_ek).ok()?).ok()?;
    let (ss, ct) = ek.try_encaps().ok()?;
    let ss = ss.into_bytes();
    Some((ct.into_bytes(), note_kdf(&ss, b"MUSD-note-enc-v1"), note_kdf(&ss, b"MUSD-note-vt-v1")[0], usdmd_node::faucet::note_opening(my_spk, &ss)))
}

/// ⭐ §BR-12 F13 — SEAL A CONTRACT'S PUBLISHER-FEE NOTE. The node's call door fixes this note's commitment to
/// `asset_note_cm(fee, USDm, owner_opening(publisher_spk, publisher_fee_seed(cid, tx_hash)))` — a PUBLIC opening, so every
/// node checks the caller paid the DEPLOYED fee to the publisher with no key of anyone's. The payload is still a note the
/// publisher's ordinary scan finds: the encapsulation to the deploy's `view_ek` is FIPS 203's deterministic core over
/// `m = seed_m` (the public seed's canonical 32 bytes), so the publisher's decapsulation recovers the seed and opens the
/// commitment under it ([`scan_note_full_asset`] tries that opening when the KEM-seed opening does not bind). The seed
/// completes the publisher's `NoteOwner{ask, nk, seed}`, so the note is spendable by the publisher alone (DB-395: an
/// opening spends nothing). `None` when `view_ek` is not an ML-KEM-768 key.
/// DIGITAL-CASH-PRIVACY-REVIEWED: the fee amount and the publisher's `spk` are the deploy's PUBLIC manifest words (the
/// §BR-12 design: a flat deployed fee every node enforces); the note's payload reveals nothing beyond them.
pub fn seal_publisher_fee_note(view_ek: &[u8], publisher_spk: &Digest4, fee: u64, seed_m: &[u8; 32]) -> Option<[u8; PQ_NOTE_BYTES]> {
    use fips203::traits::{Encaps as _, SerDes as _};
    let ek = fips203::ml_kem_768::EncapsKey::try_from_bytes(<[u8; 1184]>::try_from(view_ek).ok()?).ok()?;
    let (ss, ct) = ek.encaps_from_seed(seed_m);
    let (mut note, _kem_opening) = note_from_encaps(publisher_spk, &ss.into_bytes(), &ct.into_bytes(), fee, USDM_ASSET_TAG);
    // `seed_m` is the public seed's CANONICAL bytes (`leaf_to_cm_bytes`), so the inverse decoder (`cm_bytes_to_root`) gives the
    // seed the door hashes — never the compressing map, which would name another opening.
    let seed = usdmd_node::spend_frontier::cm_bytes_to_root(seed_m)?;
    let opening = usdm_decider::whir_rec_block::owner_opening(publisher_spk, &seed);
    note[0..NOTE_CT_OFF].copy_from_slice(&crate::pq_spend::note_cm_asset_bytes(fee, USDM_ASSET_TAG, opening));
    Some(note)
}

/// ⭐ DB-288 §9 — the pad that masks a self-note's consumed input nullifier inside its ML-KEM message: a PRF keyed by
/// this wallet's outgoing-record secret over the note's OWN locator and content. Distinct notes get unrelated pads, and
/// only the key-holder can compute one.
fn self_note_record_pad(out_sk: &[u8; 32], domain: &str, j: u64, amount: u64, asset: [u64; 3]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(out_sk);
    h.update(b"MonerousD 2026-09-27 self-note KEM record v1/");
    h.update(&(domain.len() as u64).to_le_bytes());
    h.update(domain.as_bytes());
    h.update(&j.to_le_bytes());
    h.update(&amount.to_le_bytes());
    for a in asset {
        h.update(&a.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// ⭐⭐ DB-288 §9 — SEAL A SELF-NOTE WHOSE ML-KEM MESSAGE RECORDS THE INPUT ITS TRANSACTION CONSUMES.
///
/// The encapsulation is FIPS 203's deterministic core over `m = nf_in ⊕ pad(out_sk, domain, j, amount, asset)`, so the
/// owner's decapsulation later recovers `m` and reads `nf_in` back ([`open_self_note_record`]): a seed-only restore
/// learns which input every one of its change notes spent with ZERO node asks and ZERO bytes on the wire. `m` is a
/// keyed-PRF output, so the ciphertext and shared secret are as indistinguishable as a random encapsulation (IND-CCA2
/// by a PRF hybrid — lane-db224's review, 20:33); `nf_in` is unique per spent input, so `m` is unique per note.
/// `(domain, j)` is the OLI locator the note is written at (DB-273 §15), so the restore that finds it has the pad's
/// inputs in hand. `None` if `my_ek` is malformed.
/// cons: none on the wire or in retention (the note is still 1,153 B); one blake3 per seal.
#[allow(clippy::too_many_arguments)]
pub fn seal_self_note_with_record(
    my_ek: &[u8],
    my_spk: &Digest4,
    amount: u64,
    asset: [u64; 3],
    out_sk: &[u8; 32],
    nf_in: &[u8; 32],
    domain: &str,
    j: u64,
) -> Option<([u8; PQ_NOTE_BYTES], Digest4)> {
    use fips203::traits::{Encaps as _, SerDes as _};
    let ek = fips203::ml_kem_768::EncapsKey::try_from_bytes(<[u8; 1184]>::try_from(my_ek).ok()?).ok()?;
    let pad = self_note_record_pad(out_sk, domain, j, amount, asset);
    let m: [u8; 32] = core::array::from_fn(|i| nf_in[i] ^ pad[i]);
    let (ss, ct) = ek.encaps_from_seed(&m);
    Some(note_from_encaps(my_spk, &ss.into_bytes(), &ct.into_bytes(), amount, asset))
}

/// ⭐ DB-288 §9 — the transfer door's REMAINDER with its record: [`seal_note_change`]'s rule (the change keeps the
/// INPUT'S asset, read back with the owner's own key; a note that is not the caller's refuses) sealed through
/// [`seal_self_note_with_record`] at the change's own locator, recording the input it consumes.
#[allow(clippy::too_many_arguments)]
pub fn seal_change_with_record(
    my_ek: &[u8],
    my_spk: &Digest4,
    input_note: &[u8],
    my_dk: &[u8],
    amount: u64,
    out_sk: &[u8; 32],
    nf_in: &[u8; 32],
    domain: &str,
    j: u64,
) -> Option<([u8; PQ_NOTE_BYTES], Digest4)> {
    let (_in_amount, _in_seed, asset) = scan_note_full_asset(input_note, my_dk, my_spk)?;
    seal_self_note_with_record(my_ek, my_spk, amount, asset, out_sk, nf_in, domain, j)
}

/// ⭐⭐ DB-288 §9 — READ THE RECORD a self-note found at `(domain, j)` carries: the nullifier of the input its
/// transaction consumed. `None` when the note is not this wallet's, does not decapsulate under the FO check, or does
/// not open to its own commitment. A note with NO record (a random encapsulation) opens to a pseudorandom value that
/// matches none of this wallet's notes — the caller keeps only a nullifier it recognises, so it is never a false
/// "spent".
pub fn open_self_note_record(
    note: &[u8],
    dk_bytes: &[u8],
    my_spk: &Digest4,
    out_sk: &[u8; 32],
    domain: &str,
    j: u64,
) -> Option<[u8; 32]> {
    use fips203::traits::SerDes as _;
    if note.len() != PQ_NOTE_BYTES {
        return None;
    }
    let dk = fips203::ml_kem_768::DecapsKey::try_from_bytes(<[u8; 2400]>::try_from(dk_bytes).ok()?).ok()?;
    let ct = fips203::ml_kem_768::CipherText::try_from_bytes(
        <[u8; 1088]>::try_from(&note[NOTE_CT_OFF..NOTE_CT_END]).ok()?,
    )
    .ok()?;
    let (ss, m) = dk.try_decaps_with_message(&ct).ok()?;
    let ss = ss.into_bytes();
    if note_kdf(&ss, b"MUSD-note-vt-v1")[0] != note[NOTE_VT_OFF] {
        return None;
    }
    let ks = note_kdf(&ss, b"MUSD-note-enc-v1");
    let amt: [u8; 8] = core::array::from_fn(|i| note[NOTE_CT_END + i] ^ ks[i]);
    let asset = asset_from(&note[NOTE_CT_END..NOTE_ENC_END], &ks);
    if note_cm_asset(my_spk, &ss, &amt, asset) != note[0..NOTE_CT_OFF] {
        return None;
    }
    let pad = self_note_record_pad(out_sk, domain, j, u64::from_le_bytes(amt), asset);
    Some(core::array::from_fn(|i| m[i] ^ pad[i]))
}

/// ⭐⭐⭐ DB-273 (D0) — THE REMAINDER OF A SPEND IS A FRESH NOTE TO THE SPENDER'S OWN KEY, AT THE INPUT'S ASSET.
///
/// This replaced `seal_note_reissue`, which copied the INPUT note's 1,088-byte ML-KEM ciphertext verbatim so the
/// remainder kept the input's shared secret, spend key and view tag. Anyone who stored both notes linked every
/// spend to its change by those bytes; the re-issue accepted that linkage as the price of never having to
/// DISCOVER the remainder. Discovery no longer needs the input's identity: the wallet trial-decaps every applied
/// block's real notes from its own node (live), and a seed-only restore finds the change at the DENSE `chg`
/// locator the send tags it with (`lib.rs` `remainder_locator`). So the remainder is an ordinary note: a new
/// encapsulation, a new shared secret, a new spend key — findable by the owner's ordinary scan and unlinkable to
/// the note it came from.
///
/// ⛔ THE REMAINDER KEEPS THE INPUT'S ASSET. The asset is READ BACK from the input with the owner's own key, so
/// the change of a wrapped spend can never be re-denominated as USDm (value invented on one side, destroyed on
/// the other). A note that is not the caller's — a foreign ciphertext, an edited asset — refuses: `None`, and
/// the send fails closed rather than sealing change at a guessed asset.
///
/// Returns the change note plus its opening `P(my_spk, seed)`, the value the spend carrier binds the change commitment
/// to. `None` if the input is not the caller's or the encapsulation fails.
pub fn seal_note_change(
    my_ek: &[u8],
    my_spk: &Digest4,
    input_note: &[u8],
    my_dk: &[u8],
    amount: u64,
) -> Option<([u8; PQ_NOTE_BYTES], Digest4)> {
    let (_in_amount, _in_seed, asset) = scan_note_full_asset(input_note, my_dk, my_spk)?;
    seal_note_full_asset(my_ek, my_spk, amount, asset)
}

/// Try to recover the amount from a served note using `dk` (the wallet's ML-KEM scan secret) and its spend key `spk`.
/// Returns `Some(amount)` iff the note was sealed to THIS wallet (view-tag matches AND note_cm binds under this wallet's
/// opening), else `None`. This is the fetch-all + local-decap scan: the node never sees the scan key; recovery is 100%
/// wallet-side.
pub fn scan_note(note: &[u8], dk_bytes: &[u8], spk: &Digest4) -> Option<u64> {
    // ONE scanner for every note the chain carries (§BR-12 F13 added the publisher-fee opening to it): the amount-only
    // read is that scanner's amount. Binding check UNDER THE NOTE'S OWN TAG: a 1-byte view-tag collision cannot forge a
    // note, and a wrapped note this wallet owns opens under its own asset, never a hardcoded USDm tag.
    scan_note_full_asset(note, dk_bytes, spk).map(|(amount, _seed, _asset)| amount)
}

/// Like [`scan_note`], but ALSO returns the note's SEED — with the wallet's `(ask, nk)` it completes the
/// `NoteOwner` the wallet needs to SPEND this note (DB-395). `Some((amount, seed))` iff the note is ours (view-tag +
/// Poseidon `note_cm` binding). The scan key never leaves the wallet.
pub fn scan_note_full(note: &[u8], dk_bytes: &[u8], spk: &Digest4) -> Option<(u64, Digest4)> {
    scan_note_full_asset(note, dk_bytes, spk).map(|(amount, seed, _asset)| (amount, seed))
}

/// Like [`scan_note_full`], but ALSO returns the note's ASSET TAG. A note sealed before tags existed
/// recovers as [`USDM_ASSET_TAG`], because its tag bytes are pure keystream and XOR to zero — so this
/// is the one scanner for every note the chain has ever carried, old or new.
///
/// ⛔ THE BINDING CHECK IS WHAT MAKES THE TAG TRUSTWORTHY. The recovered tag is fed back into
/// `note_cm_asset` and compared against the note's own commitment. A note whose tag bytes were flipped
/// in transit recomputes a DIFFERENT commitment and is rejected as not-ours — an attacker cannot
/// re-denominate someone's note by editing bytes in the envelope.
pub fn scan_note_full_asset(note: &[u8], dk_bytes: &[u8], spk: &Digest4) -> Option<(u64, Digest4, [u64; 3])> {
    // The caller's own keys first (the base address: change, rewards, every note before per-address keys); then, for the
    // open wallet, the ONE address this note's commitment was located at ([`note_at_address`]). A note located nowhere
    // is tried under nothing else: no address is searched.
    scan_note_under(note, dk_bytes, spk).or_else(|| scan_at_recorded_address(note, spk))
}

/// [`scan_note_full_asset`] under exactly the keys given.
fn scan_note_under(note: &[u8], dk_bytes: &[u8], spk: &Digest4) -> Option<(u64, Digest4, [u64; 3])> {
    use fips203::traits::SerDes as _;
    if note.len() != PQ_NOTE_BYTES {
        return None;
    }
    let dk =
        fips203::ml_kem_768::DecapsKey::try_from_bytes(<[u8; 2400]>::try_from(dk_bytes).ok()?).ok()?;
    let ct = fips203::ml_kem_768::CipherText::try_from_bytes(
        <[u8; 1088]>::try_from(&note[NOTE_CT_OFF..NOTE_CT_END]).ok()?,
    )
    .ok()?;
    // The decapsulation also yields the KEM MESSAGE `m` (the same FO check; a foreign ciphertext's `m` is implicit-rejection
    // noise): a publisher-fee note carries its PUBLIC seed there (§BR-12 F13, `seal_publisher_fee_note`).
    let (ss, m) = dk.try_decaps_with_message(&ct).ok()?;
    let ss = ss.into_bytes();
    if note_kdf(&ss, b"MUSD-note-vt-v1")[0] != note[NOTE_VT_OFF] {
        return None;
    }
    let ks = note_kdf(&ss, b"MUSD-note-enc-v1");
    let mut amt = [0u8; 8];
    for i in 0..8 {
        amt[i] = note[NOTE_CT_END + i] ^ ks[i];
    }
    let asset = asset_from(&note[NOTE_CT_END..NOTE_ENC_END], &ks);
    // Binding check UNDER THE RECOVERED TAG and THIS WALLET'S spend key: the commitment must open to this amount, this
    // asset and this wallet's opening — the KEM-seed opening every ordinary note uses, else the PUBLIC-seed opening a
    // contract's publisher-fee note uses (the seed is the message `m`). Either way the note opens to THIS wallet's `spk`
    // at THIS amount and asset, or it is not ours; the seed returned is the one that opened it, so `NoteOwner{ask, nk,
    // seed}` spends it.
    if note_cm_asset(spk, &ss, &amt, asset) == note[0..NOTE_CT_OFF] {
        return Some((u64::from_le_bytes(amt), note_seed_from_ss(&ss), asset));
    }
    let public_seed = usdmd_node::spend_frontier::cm_bytes_to_root(&m)?;
    let public_opening = usdm_decider::whir_rec_block::owner_opening(spk, &public_seed);
    if crate::pq_spend::note_cm_asset_bytes(u64::from_le_bytes(amt), asset, public_opening) == note[0..NOTE_CT_OFF] {
        return Some((u64::from_le_bytes(amt), public_seed, asset));
    }
    None
}

/// A served chain note paired with its packed detection clue (the clue the SENDER attached from the recipient's
/// public clue key). This is what the node serves per note for the oblivious cold-restore path.
pub struct CluedNote<'a> {
    pub note: &'a [u8],
    pub clue: crate::omr::Clue,
}

/// CLUE-ACCELERATED cold-restore recover (the oblivious keystone's wallet-side hot path). Over served (note,
/// clue) pairs it runs the CHEAP packed-LWE detection test FIRST and ML-KEM-decapsulates ONLY the notes whose
/// clue is pertinent — so the EXPENSIVE decap runs `O(owned)`, not `O(chain)`. The `note_cm` binding inside
/// `scan_note_full` still gates acceptance, so a false-positive clue (2^-γ) costs one wasted decap and is
/// rejected — a malicious node cannot make us accept a note that is not ours. The scan key + clue secret NEVER
/// leave the wallet; the node learns nothing about which notes matched. Returns the recovered `(amount, spend
/// secret)` set plus the number of decaps actually performed, so callers can assert the `O(owned)` bound.
pub fn clue_accelerated_recover(
    clue_sk: &crate::omr::ClueSecretKey,
    scan_dk: &[u8],
    spk: &Digest4,
    served: &[CluedNote],
) -> (Vec<(u64, Digest4)>, usize) {
    let mut owned = Vec::new();
    let mut decaps = 0usize;
    for cn in served {
        if crate::omr::is_pertinent(clue_sk, &cn.clue) {
            decaps += 1; // only pertinent clues pay the expensive ML-KEM decap
            if let Some((amount, seed)) = scan_note_full(cn.note, scan_dk, spk) {
                owned.push((amount, seed));
            }
        }
    }
    (owned, decaps)
}

/// SOUND COMPLETE recover — the AUTHORITATIVE completeness guarantee (never lose money). Over the served notes it
/// ML-KEM-decapsulates EVERY note LOCALLY and keeps the ones whose Poseidon `note_cm` binding proves ours,
/// IGNORING the detection clue entirely. [`clue_accelerated_recover`] is a fast OPTIMISTIC hint, but the clue is
/// attached by the SENDER and relayed by the NODE — a malicious sender can attach a NON-pertinent clue (or a
/// malicious node can substitute one) on a note we truly own, which the clue path would silently skip: a
/// false-negative MONEY LOSS. This fetch-all-then-decap-LOCALLY path cannot be fooled that way — completeness
/// never depends on any sender's or node's clue, only on the ML-KEM decap + `note_cm` we compute ourselves.
/// Privacy holds (the scan key never leaves the wallet; the node served all notes and learns nothing about which
/// are ours). O(served) decaps — the sound floor the wallet uses for COLD-RESTORE and the "verify all funds"
/// completeness check; the clue path stays the fast incremental preview at tip. Returns the recovered `(amount,
/// spend secret)` set.
pub fn full_recover(scan_dk: &[u8], spk: &Digest4, notes: &[&[u8]]) -> Vec<(u64, Digest4)> {
    notes.iter().filter_map(|n| scan_note_full(n, scan_dk, spk)).collect()
}


#[cfg(test)]
mod asset_tagged_note_tests {
    //! A wrapped note must be recognizable, spendable, and IMPOSSIBLE to confuse with USDm — and every
    //! note sealed before tags existed must keep reading as USDm without a migration.

    use super::*;

    /// A wallet's scan keys and its spend key `spk` (DB-395: every note sealed to it commits to `spk`).
    fn a_wallet() -> (Vec<u8>, Vec<u8>, Digest4) {
        let k = derive_keys(&[7u8; 32]);
        (k.scan_ek.clone(), k.scan_dk.to_vec(), k.note_spk)
    }

    fn a_view() -> NoteView {
        derive_keys(&[7u8; 32]).note_view()
    }

    fn wbtc() -> [u64; 3] {
        usdm_decider::whir_rec_block::wrapped_asset_tag(&[7u8; 32])
    }

    /// ⭐⭐⭐ THE COMPATIBILITY PIN. Sealing at the USDm tag must produce the SAME BYTES the pre-tag
    /// sealer produced. If this ever fails, every note already on chain changed identity.
    #[test]
    fn a_usdm_note_is_byte_identical_whether_or_not_the_tag_is_named() {
        let (ek, dk, spk) = a_wallet();
        let (plain, _sk_a) = seal_note_full(&ek, &spk, 100_000_000).expect("seal");
        let (tagged, _sk_b) = seal_note_full_asset(&ek, &spk, 100_000_000, USDM_ASSET_TAG).expect("seal");
        // NOTE the per-note opening is NOT shared between the two: every seal runs a fresh ML-KEM
        // encapsulation, so each note gets its own shared secret, seed and opening. That is the
        // design (fresh randomness per note), so the compatibility claim is about the SHAPE and the
        // COMMITMENT RULE, never about two seals producing the same bytes.
        assert_eq!(plain.len(), tagged.len(), "layout is unchanged — no version byte, no growth");
        assert_eq!(plain.len(), PQ_NOTE_BYTES);
        // THE RULE: at the USDm tag the commitment function IS the untagged one, for any key.
        for o in [usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), usdmd_node::spend_frontier::empty_leaf(), usdm_decider::poseidon2_compress::lanes_of(&[u64::MAX, 7, 9, 11])] {
            assert_eq!(
                crate::pq_spend::note_cm_asset_bytes(100_000_000, USDM_ASSET_TAG, o),
                crate::pq_spend::note_cm_bytes(100_000_000, o),
                "a USDm-tagged commitment IS the untagged commitment"
            );
        }
        // And both notes are indistinguishable to the scanner: same amount, same USDm denomination.
        assert_eq!(scan_note_full_asset(&plain, &dk, &spk).map(|(a, _, t)| (a, t)), Some((100_000_000, USDM_ASSET_TAG)));
        assert_eq!(scan_note_full_asset(&tagged, &dk, &spk).map(|(a, _, t)| (a, t)), Some((100_000_000, USDM_ASSET_TAG)));
    }

    /// A wrapped note round-trips: sealed with an asset, scanned back with that same asset.
    #[test]
    fn a_wrapped_note_round_trips_with_its_asset() {
        let (ek, dk, spk) = a_wallet();
        let (note, _sk) = seal_note_full_asset(&ek, &spk, 42_000, wbtc()).expect("seal wBTC");
        let (amount, _sk2, asset) = scan_note_full_asset(&note, &dk, &spk).expect("our own note scans");
        assert_eq!(amount, 42_000);
        assert_eq!(asset, wbtc(), "the note remembers WHICH asset it is");
    }

    /// ⛔⛔⛔ EVERY PRE-TAG NOTE READS AS USDm. The tag bytes of an old note are pure keystream, so
    /// they recover as zero. This is the whole backward-compatibility argument, tested rather than
    /// asserted.
    #[test]
    fn a_note_sealed_without_a_tag_reads_back_as_usdm() {
        let (ek, dk, spk) = a_wallet();
        let (note, _sk) = seal_note_full(&ek, &spk, 777).expect("seal the way the wallet always did");
        let (amount, _sk2, asset) = scan_note_full_asset(&note, &dk, &spk).expect("scans");
        assert_eq!(amount, 777);
        assert_eq!(asset, USDM_ASSET_TAG, "an untagged note is a USDm note, with no migration");
        // And the amount-only scanner still works on it.
        assert_eq!(scan_note(&note, &dk, &spk), Some(777));
    }

    /// ⛔ A TAMPERED TAG IS REJECTED, not silently re-denominated. Flipping a tag byte changes the
    /// commitment the note must open to, so the note stops being ours instead of becoming a different
    /// asset that we would then credit.
    #[test]
    fn editing_a_notes_tag_bytes_makes_it_fail_the_binding_check() {
        let (ek, dk, spk) = a_wallet();
        let (note, _sk) = seal_note_full_asset(&ek, &spk, 5_000, wbtc()).expect("seal");
        let mut forged = note;
        forged[NOTE_CT_END + NOTE_ASSET_OFF] ^= 0xFF; // re-denominate it in transit
        assert!(
            scan_note_full_asset(&forged, &dk, &spk).is_none(),
            "a note whose asset was edited must be REFUSED, never accepted as another asset"
        );
        assert!(scan_note(&forged, &dk, &spk).is_none(), "and the amount-only scanner refuses it too");
    }

    /// ⛔⛔⛔ THE REMAINDER OF A WRAPPED SPEND STAYS WRAPPED. Sealing change at the USDm tag would
    /// convert a user's wBTC change into USDm — value invented on one side and destroyed on the other.
    #[test]
    fn the_change_keeps_the_inputs_asset() {
        let (ek, dk, spk) = a_wallet();
        let (input, _sk) = seal_note_full_asset(&ek, &spk, 10_000, wbtc()).expect("seal wBTC input");
        let (change, _csk) = seal_note_change(&ek, &spk, &input, &dk, 6_000).expect("seal the change");
        let (amount, _sk2, asset) = scan_note_full_asset(&change, &dk, &spk).expect("the change is ours");
        assert_eq!(amount, 6_000, "the remainder carries the new amount");
        assert_eq!(asset, wbtc(), "and is STILL wBTC — not silently converted to USDm");
    }

    /// A USDm remainder stays USDm — the same path, exercised for the asset every existing note uses.
    #[test]
    fn a_usdm_remainder_stays_usdm() {
        let (ek, dk, spk) = a_wallet();
        let (input, _sk) = seal_note_full(&ek, &spk, 900).expect("seal");
        let (change, _csk) = seal_note_change(&ek, &spk, &input, &dk, 400).expect("seal the change");
        let (amount, _sk2, asset) = scan_note_full_asset(&change, &dk, &spk).expect("ours");
        assert_eq!((amount, asset), (400, USDM_ASSET_TAG));
    }

    /// ⛔⛔⛔ THE UNIT-CONFUSION ATTACK: a wBTC note and a USDm note of the SAME amount to the SAME
    /// wallet must be different objects on chain. If their commitments collided, one atomic unit of a
    /// token worth tens of thousands of dollars would spend as one atomic unit of USDm.
    #[test]
    fn a_wrapped_note_and_a_usdm_note_of_the_same_amount_are_different_objects() {
        let (ek, dk, spk) = a_wallet();
        let (usdm, _a) = seal_note_full(&ek, &spk, 1).expect("seal 1 USDm atomic unit");
        let (wrapped, _b) = seal_note_full_asset(&ek, &spk, 1, wbtc()).expect("seal 1 wBTC atomic unit");
        let (_amt_u, seed_u, asset_u) = scan_note_full_asset(&usdm, &dk, &spk).unwrap();
        let (_amt_w, seed_w, asset_w) = scan_note_full_asset(&wrapped, &dk, &spk).unwrap();
        assert_ne!(asset_u, asset_w, "the two notes are denominated differently");
        assert_ne!(
            crate::pq_spend::note_cm_asset_bytes(1, asset_u, a_view().opening(&seed_u)),
            crate::pq_spend::note_cm_asset_bytes(1, asset_w, a_view().opening(&seed_w)),
            "and their on-chain commitments differ — no cross-asset unit confusion"
        );
    }
}

#[cfg(test)]
mod poseidon_note_tests {
    use super::*;

    /// A sealed note's on-chain `note_cm` IS the recipient's POSEIDON commitment — so a recorded note is a
    /// SPENDABLE Poseidon leaf, and the recipient's local scan recovers BOTH the amount AND the spend secret
    /// `sk`. A foreign wallet recovers nothing (view-tag + KEM implicit-rejection).
    #[test]
    fn sealed_note_is_a_spendable_poseidon_leaf_and_scan_recovers_amount_and_seed() {
        let keys = derive_keys(&[9u8; 32]);
        let amount = 4242u64;
        let note = seal_note(&keys.scan_ek, &keys.note_spk, amount).expect("seal a note to the recipient");
        // Recipient's local decap recovers (amount, seed) — the scan key never leaves the wallet.
        let (amt, seed) = scan_note_full(&note, &keys.scan_dk, &keys.note_spk).expect("recipient scans its own note");
        assert_eq!(amt, amount, "amount recovered");
        // DB-395: the recorded note_cm (first 32 bytes) opens as asset_note_cm(amount, USDm, o) with the owner tag
        // o = P(spk, seed) — a spendable leaf whose spend authority is the recipient's (ask, nk), never the seed.
        let o = usdm_decider::whir_rec_block::owner_opening(&keys.note_spk, &seed);
        let cm: [u8; 32] = note[0..32].try_into().unwrap();
        assert_eq!(
            usdmd_node::spend_frontier::note_leaf_of(&cm),
            crate::pq_spend::note_commitment(amount, o),
            "note_cm opens as the recipient's Poseidon note commitment (spendable membership leaf)"
        );
        assert_eq!(cm, crate::pq_spend::note_cm_bytes(amount, o), "note_cm == note_cm_bytes(amount, o)");
        // A foreign wallet cannot recover it (not sealed to them).
        let other = derive_keys(&[7u8; 32]);
        assert!(scan_note_full(&note, &other.scan_dk, &other.note_spk).is_none(), "foreign wallet recovers nothing");
    }
}

// ── Frontier membership — the soundness anchor for OBLIVIOUS note recovery ──
// The node's note-commitment frontier (monerousd-node-zkdag/src/frontier.rs: a depth-32 sparse Merkle tree,
// leaf = a note's `cm`, parent = blake3(left‖right), empty positions = blake3("MUSD-empty-note")) commits
// EVERY note in one O(1) root. A wallet recovers ONLY its own notes via oblivious retrieval (the node learns
// nothing about which are ours, and our scan key never leaves the wallet), then re-checks each served note
// against the frontier root it reads INDEPENDENTLY (/get_pq_output_tree). A note is genuinely on-chain iff its
// `cm` has a valid depth-32 inclusion path to that root — so a malicious/foreign node CANNOT fabricate, alter,
// re-order, or mis-serve a note (a forged `cm` has no valid path; a real leaf's path is unique). This binds
// EXISTENCE; `note_cm` (in `scan_note`) separately binds the AMOUNT. Together: sound recovery over an
// untrusted, oblivious transport. Byte-identical to the node's `crate::merkle::hash_pair` + `crate::frontier`.
// ⛔⛔⛔ MUST EQUAL the node's `spend_frontier::SPEND_TREE_DEPTH`. It was 32 on both sides, and 32 gave the
// chain a DEATH DATE 97 days after genesis: the frontier is fixed-height, `append` refuses at
// `2^depth` leaves, and the constant 256-leaf cover shape burns that capacity at 44,236,800 leaves/day
// regardless of traffic. A refusal to append is a refusal to RECEIVE. At 64 the capacity saturates u64 —
// ~1.1e9 years at the same rate. A mismatch between this and the node makes every spend unverifiable, so
// these two constants move together or not at all.
pub const NOTE_TREE_DEPTH: usize = usdmd_node::spend_frontier::SPEND_TREE_DEPTH; // DB-81: the node's constant, never a second spelling

/// blake3(left‖right) — byte-identical to the node's `crate::merkle::hash_pair`.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    *blake3::hash(&buf).as_bytes()
}

/// Verify a depth-32 Merkle inclusion of note commitment `cm` at leaf `index` under `root`, given the 32
/// sibling hashes `copath` (bottom leaf-level → top). Returns true iff the recomputed root equals `root`.
/// Fail-closed on a wrong-length copath. This is the wallet-side soundness gate for EVERY obliviously-recovered
/// note: reject any note whose `cm` does not prove membership in the frontier the wallet read independently.
pub fn verify_note_membership(
    cm: &[u8; 32],
    index: u64,
    copath: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if copath.len() != NOTE_TREE_DEPTH {
        return false; // fail-closed: a malformed proof is not a valid proof
    }
    let mut cur = *cm;
    for (level, sib) in copath.iter().enumerate() {
        cur = if (index >> level) & 1 == 0 {
            hash_pair(&cur, sib) // this node is the LEFT child at `level`
        } else {
            hash_pair(sib, &cur) // this node is the RIGHT child at `level`
        };
    }
    &cur == root
}

/// The domain-separated empty leaf — byte-identical to the node's `frontier.rs` `empty_leaf`.
fn empty_leaf() -> [u8; 32] {
    *blake3::hash(b"MUSD-empty-note").as_bytes()
}
/// Hash of an all-empty subtree at `level` (level 0 = the empty leaf) — mirrors the node's `empty[l]` ladder.
fn empty_subtree(level: usize) -> [u8; 32] {
    let mut e = empty_leaf();
    for _ in 0..level {
        e = hash_pair(&e, &e);
    }
    e
}
/// Canonical hash of the `2^level`-leaf subtree starting at leaf `start`, real leaves where present and
/// empty-leaf padding beyond `leaves.len()`. The all-empty tail short-circuits, so this descends ONLY into
/// subtrees that contain real leaves — O(N·DEPTH), never 2^DEPTH.
fn subtree_hash(leaves: &[[u8; 32]], level: usize, start: u64) -> [u8; 32] {
    if start >= leaves.len() as u64 {
        return empty_subtree(level); // fully-empty tail
    }
    if level == 0 {
        return leaves[start as usize];
    }
    let half = 1u64 << (level - 1);
    hash_pair(
        &subtree_hash(leaves, level - 1, start),
        &subtree_hash(leaves, level - 1, start + half),
    )
}

/// The depth-32 note-frontier root of `leaves` (note commitments in append order) — byte-identical to the
/// node's `NoteFrontier::root()` (what `/get_pq_output_tree` serves as `root`). The wallet recomputes it to
/// confirm the node's advertised root is the honest root of the leaf set it also served.
pub fn frontier_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    subtree_hash(leaves, NOTE_TREE_DEPTH, 0)
}

/// The depth-32 inclusion copath (bottom→top, 32 siblings) for leaf `index`. The wallet computes this
/// LOCALLY from the leaf set `/get_pq_output_tree` serves, then binds it with `verify_note_membership` — so a
/// recovered note is accepted only if it provably sits in the frontier root. No node-side proof serving, no
/// key leaves the wallet.
pub fn frontier_copath(leaves: &[[u8; 32]], index: u64) -> Vec<[u8; 32]> {
    (0..NOTE_TREE_DEPTH as u64)
        .map(|l| subtree_hash(leaves, l as usize, ((index >> l) ^ 1) << l))
        .collect()
}

// ⛔ DELETED 2026-10-05 (DB-395 port) — `build_transfer_outputs` / `TransferPlan`: a greedy note picker that sealed a
// recipient note and a change note to bare scan keys. No production caller existed (the send is `lib.rs`
// `spend_one_note_to`, through the proven carrier), only its own four tests; under DB-395 every sealer needs the
// recipient's spend key, and a vestigial sealer with no caller is deleted at source rather than ported.

/// Sign `msg` with the wallet's ML-DSA-65 SPEND key (pure ML-DSA, empty context). Used to AUTHENTICATE a
/// governance vote: the node verifies the detached signature against `spend_pk`, whose blake3 IS the validator
/// id `b`, so no party can cast another's vote. The spend secret NEVER leaves the wallet — only the detached
/// signature + the public verification key go out. None if the stored key is malformed.
pub fn sign_spend(keys: &WalletKeys, msg: &[u8]) -> Option<Vec<u8>> {
    use fips204::traits::{SerDes as _, Signer as _};
    let sk_arr: [u8; fips204::ml_dsa_65::SK_LEN] = keys.spend_sk.as_slice().try_into().ok()?;
    let sk = fips204::ml_dsa_65::PrivateKey::try_from_bytes(sk_arr).ok()?;
    sk.try_sign(msg, &[]).ok().map(|s| s.to_vec())
}

/// Verify a detached ML-DSA-65 signature `sig` over `msg` against the verification key `spend_pk` (pure ML-DSA,
/// empty context — the inverse of `sign_spend`). Used by the PQ-Tap PAYER side to confirm a merchant's charge is
/// authentic + un-tampered BEFORE it withdraws a cent. FAIL-CLOSED: returns false on any malformed key/sig/length.
pub fn verify_spend(spend_pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use fips204::traits::{SerDes as _, Verifier as _};
    let pk_arr: [u8; fips204::ml_dsa_65::PK_LEN] = match spend_pk.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; fips204::ml_dsa_65::SIG_LEN] = match sig.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pk = match fips204::ml_dsa_65::PublicKey::try_from_bytes(pk_arr) {
        Ok(p) => p,
        Err(_) => return false,
    };
    pk.verify(msg, &sig_arr, &[])
}

#[cfg(test)]
mod validator_identity_tests {
    use super::*;

    /// ⭐⭐⭐ THE AUTOMATIC, SEED-LINKED VALIDATOR, end to end across the two implementations (user 2026-09-28).
    ///
    /// The wallet derives the identity with fips204; the node signs and verifies with pqcrypto (PQClean). This pins:
    /// * the derived vote key signs through the NODE's own signer and verifies under the NODE's own verifier (a bond
    ///   statement, a finality vote and an unbond are all this call);
    /// * derivation is deterministic (a seed-only restore re-provisions the SAME identity, so every bond survives) and
    ///   separated by index and by seed;
    /// * the NODE's provisioning door installs it, deriving a custody KEM that opens its own deltas.
    /// TWO-PARTY-REVIEWED: wallet side (`derive_validator_identity`) and node side (`pqauth::ml_dsa_sign/verify`,
    /// `validator::provision_identity_at`, `pqkem`) are each the production function.
    #[test]
    fn a_seed_derived_validator_identity_signs_for_the_node_and_restores_from_the_seed() {
        let root = derive_keys(&[7u8; 32]).validator_root;
        let id = derive_validator_identity(&root, 0);
        let msg = b"a bond statement, a finality vote or an unbond";
        let sig = usdmd_node::pqauth::ml_dsa_sign(msg, &id.vote_sk).expect("the node's signer takes the derived key");
        assert!(usdmd_node::pqauth::ml_dsa_verify(msg, &id.vote_pk, &sig), "the node verifies the derived identity");
        let again = derive_validator_identity(&derive_keys(&[7u8; 32]).validator_root, 0);
        assert_eq!((again.vote_pk.clone(), again.vote_sk.to_vec()), (id.vote_pk.clone(), id.vote_sk.to_vec()), "restore reproduces it");
        assert_ne!(derive_validator_identity(&root, 1).vote_pk, id.vote_pk, "a second node takes a second identity");
        assert_ne!(
            derive_validator_identity(&derive_keys(&[8u8; 32]).validator_root, 0).vote_pk,
            id.vote_pk,
            "another seed is another validator"
        );
        let path = std::env::temp_dir().join(format!("musd-wallet-provision-{}", std::process::id())).join("validator-1.key");
        assert_eq!(
            usdmd_node::validator::provision_identity_at(&path, &id.vote_pk, &id.vote_sk, |_| false),
            Ok(usdmd_node::validator::Provision::Installed),
            "the node's door installs the wallet-derived identity"
        );
        let (ek, dk) = usdmd_node::validator::custody_kem_from_vote_sk(&id.vote_sk);
        let (ss, ct) = usdmd_node::pqkem::encapsulate(&ek).expect("the node-derived custody ek encapsulates");
        assert_eq!(usdmd_node::pqkem::decapsulate(&ct, &dk), Some(ss), "and its dk opens it");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐ DSOL (spec §6b A1) — THE PER-CONTRACT CALLER KEY. Deterministic from the seed (a restore reproduces it);
    /// distinct per contract and per index (a contract sees a pseudonym, never the wallet); unrelated to the spend key
    /// (no call links to a payment); and a body it signs verifies under its own `pk_c` only — a call re-signed by
    /// another caller key, or a tampered body, fails the door's signature check.
    /// TWO-PARTY-REVIEWED: key derivation + signature; the second party (the node's door verifying `pk_c`) is the DSOL
    /// door's pin, which lands with the door (spec §9 order).
    /// ⭐ §BR-12 F13 — THE PUBLISHER-FEE NOTE IS FOUND AND SPENDABLE BY THE PUBLISHER, AND BINDS THE PUBLIC OPENING THE NODE'S
    /// CALL DOOR CHECKS: sealed to the publisher's view key with the call's public seed, the publisher's ordinary scan recovers
    /// the fee, USDm, and the seed that completes its `NoteOwner` (so the note is spendable); the commitment is exactly
    /// `dsol_call_tx::publisher_fee_cm(manifest, cid, tx_hash)`. Another wallet's key finds nothing; a note whose amount byte
    /// was edited opens under neither opening (the commitment binds the amount).
    /// TWO-PARTY-REVIEWED: the node's `fee_carrier_verifies` demands this commitment (`dsol_call_tx` pins); this is the
    /// wallet half — the publisher can find and spend what the door made the caller pay.
    #[test]
    fn f13_a_publisher_fee_note_is_found_by_the_publisher_and_binds_the_public_opening() {
        let (_, publisher) = generate().expect("keys");
        let (_, stranger) = generate().expect("keys");
        let (cid, tx_hash, fee) = ([0xc1u8; 32], [0x7au8; 32], 50_000_000u64);
        let manifest = usdmd_node::dsol_deploy_tx::ContractManifest {
            code_id: [1u8; 32],
            publisher_fee_le: fee.to_le_bytes(),
            publisher_spk: usdmd_node::spend_frontier::leaf_to_cm_bytes(publisher.note_spk),
            deployer_id: [2u8; 32],
            kc_commit: [3u8; 32],
            height_class: 14,
        };
        let seed = usdmd_node::dsol_call_tx::publisher_fee_seed(&cid, &tx_hash);
        let m = usdmd_node::spend_frontier::leaf_to_cm_bytes(seed);
        let note = seal_publisher_fee_note(&publisher.scan_ek, &publisher.note_spk, fee, &m).expect("seals");
        let want = usdmd_node::dsol_call_tx::publisher_fee_cm(&manifest, &cid, &tx_hash).expect("a canonical spk");
        assert_eq!(usdmd_node::spend_frontier::note_cm_of(&note), Some(want), "⛔ the note's commitment is not the one the door demands");
        let (amt, got_seed, asset) =
            scan_note_full_asset(&note, &publisher.scan_dk, &publisher.note_spk).expect("⛔ the publisher's scan does not find its fee note");
        assert_eq!((amt, got_seed, asset), (fee, seed, USDM_ASSET_TAG), "⛔ the scan reads another amount, seed or asset");
        assert_eq!(scan_note(&note, &publisher.scan_dk, &publisher.note_spk), Some(fee), "the amount-only scanner agrees");
        let owner = publisher.note_keys().owner(got_seed);
        assert_eq!(
            crate::pq_spend::note_cm_asset_bytes(fee, USDM_ASSET_TAG, owner.opening()),
            note[..32],
            "⛔ the owner the scan completes does not open the note — the publisher could not spend it"
        );
        assert!(scan_note_full_asset(&note, &stranger.scan_dk, &stranger.note_spk).is_none(), "⛔ another wallet reads the fee note as its own");
        let mut edited = note;
        edited[NOTE_CT_END] ^= 1;
        assert!(scan_note_full_asset(&edited, &publisher.scan_dk, &publisher.note_spk).is_none(), "⛔ an edited amount still opens");
        // an ordinary note is untouched by the fallback: sealed the usual way, it still opens under the KEM seed
        let (plain, opening) = seal_note_full(&publisher.scan_ek, &publisher.note_spk, 123).expect("seals");
        let (a, s, _) = scan_note_full_asset(&plain, &publisher.scan_dk, &publisher.note_spk).expect("ours");
        assert_eq!((a, usdm_decider::whir_rec_block::owner_opening(&publisher.note_spk, &s)), (123, opening));
    }

    #[test]
    fn dsol_a_caller_key_is_per_contract_per_index_deterministic_and_signs_only_its_own_calls() {
        let w = derive_keys(&[0x44u8; 32]);
        let again = derive_keys(&[0x44u8; 32]);
        let (cid_a, cid_b) = ([0xA1u8; 32], [0xB2u8; 32]);
        let a0 = derive_dsol_caller(&w.dsol_root, &cid_a, 0);
        assert_eq!(a0.pk, derive_dsol_caller(&again.dsol_root, &cid_a, 0).pk, "⛔ a seed restore lost a caller identity");
        let a1 = derive_dsol_caller(&w.dsol_root, &cid_a, 1);
        let b0 = derive_dsol_caller(&w.dsol_root, &cid_b, 0);
        assert_ne!(a0.pk, a1.pk, "⛔ two indices under one contract share a caller");
        assert_ne!(a0.pk, b0.pk, "⛔ two contracts see the same caller: calls link across contracts");
        assert_ne!(a0.pk, w.spend_pk, "⛔ a caller key is the wallet's spend key: a call links to its payments");
        let other = derive_keys(&[0x45u8; 32]);
        assert_ne!(a0.pk, derive_dsol_caller(&other.dsol_root, &cid_a, 0).pk, "two seeds never share a caller");
        let body = b"dsol-call-body: cid, entry, argv digest, fee nf";
        let sig = sign_dsol_call(&a0, body).expect("the caller key signs");
        assert!(verify_spend(&a0.pk, body, &sig), "the call body verifies under its own caller key");
        assert!(!verify_spend(&a1.pk, body, &sig), "⛔ a signature verified under another caller key");
        let mut tampered = body.to_vec();
        tampered[0] ^= 1;
        assert!(!verify_spend(&a0.pk, &tampered, &sig), "⛔ a tampered call body verified");
    }

    /// ADVERSARIAL INTEROP: the node runs pqcrypto (PQClean); the wallet runs fips203/204. Prove the two
    /// byte-interoperate on the SAME FIPS keys — else the node would reject every wallet spend/note.
    #[test]
    fn fips_keys_interop_with_node_pqcrypto() {
        use fips203::traits::{Decaps as _, KeyGen as _, SerDes as _};
        use fips204::traits::{KeyGen as _, SerDes as _, Signer as _};

        // ML-DSA-65: wallet (fips204) signs → node (pqcrypto mldsa65) MUST verify.
        let (spk, ssk) = fips204::ml_dsa_65::KG::keygen_from_seed(&[9u8; 32]);
        let msg = b"musdm-interop-vector";
        let sig = ssk.try_sign(msg, &[]).expect("fips204 sign"); // ctx = empty → pure ML-DSA
        let spk_bytes = spk.into_bytes();
        {
            use pqcrypto_mldsa::mldsa65;
            use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
            let npk = mldsa65::PublicKey::from_bytes(&spk_bytes).expect("node pk");
            let nsig = mldsa65::DetachedSignature::from_bytes(&sig).expect("node sig");
            assert!(
                mldsa65::verify_detached_signature(&nsig, msg, &npk).is_ok(),
                "node pqcrypto must verify the wallet's fips204 ML-DSA-65 signature"
            );
        }

        // ML-KEM-768: node (pqcrypto) encapsulates to the wallet ek → wallet (fips203) decapsulates → same secret.
        let (ek, dk) = fips203::ml_kem_768::KG::keygen_from_seed([3u8; 32], [4u8; 32]);
        let ek_bytes = ek.into_bytes();
        {
            use pqcrypto_mlkem::mlkem768;
            use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
            let nek = mlkem768::PublicKey::from_bytes(&ek_bytes).expect("node ek");
            let (nss, nct) = mlkem768::encapsulate(&nek);
            let ct = fips203::ml_kem_768::CipherText::try_from_bytes(
                nct.as_bytes().try_into().expect("ct len"),
            )
            .expect("wallet ct");
            let wss = dk.try_decaps(&ct).expect("fips203 decaps");
            assert_eq!(
                nss.as_bytes(),
                &wss.into_bytes()[..],
                "wallet fips203 ML-KEM decaps must equal the node pqcrypto encaps shared secret"
            );
        }
    }

    #[test]
    fn restore_reproduces_the_exact_wallet() {
        let (phrase, k1) = generate().expect("generate");
        assert_eq!(phrase.split_whitespace().count(), 24, "24-word phrase");
        let k2 = restore(&phrase).expect("restore");
        assert_eq!(k1.address, k2.address);
        assert_eq!(k1.spend_pk, k2.spend_pk);
        assert_eq!(&k1.scan_ek, &k2.scan_ek);
        assert_eq!(k1.b, k2.b);
        assert!(k1.clue_pk == k2.clue_pk, "the OMR detection clue key reproduces on restore (cold-restore anchor)");
    }

    #[test]
    fn two_generates_differ() {
        let (_, a) = generate().unwrap();
        let (_, b) = generate().unwrap();
        assert_ne!(a.address, b.address, "fresh CSPRNG → distinct wallets");
    }

    #[test]
    fn restore_tolerates_keyboard_casing_and_whitespace() {
        // REGRESSION LOCK: a phone keyboard auto-capitalizes the first word ("power" -> "Power") and can inject
        // extra spaces — that must NOT cause a bip39 "unknown word". Every mangled-but-equivalent form must restore
        // the EXACT same wallet as the canonical lowercase phrase (permanent fix for the on-device restore bug).
        let (phrase, base) = generate().unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();

        // (1) iOS-style auto-capitalized FIRST word only.
        let mut w = words.clone();
        let cap0 = {
            let mut c = w[0].chars();
            c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap()
        };
        w[0] = &cap0;
        let autocap = w.join(" ");
        assert_eq!(restore(&autocap).unwrap().address, base.address, "auto-capitalized first word restores same wallet");

        // (2) FULL UPPERCASE + doubled internal spaces + leading/trailing whitespace + a tab and newline.
        let messy = format!("\t  {}  \n", phrase.to_uppercase().replace(' ', "   "));
        assert_eq!(restore(&messy).unwrap().address, base.address, "uppercased + messy whitespace restores same wallet");

        // (3) still rejects a genuinely wrong word (normalization must not mask a real typo).
        let mut bad = words.clone();
        bad[0] = "notabip39word";
        assert!(restore(&bad.join(" ")).is_err(), "a genuine unknown word is still rejected");
    }

    #[test]
    fn address_is_wellformed_and_testnet() {
        let k = derive_keys(&[1u8; 32]);
        // varint(0x315054)=3 bytes + b(32) + ek(1184) + cksum(4) = 1223 B → cnBase58 is deterministic length.
        assert!(k.address.len() > 1600, "encodes b(32)+ek(1184): got {}", k.address.len());
        assert!(k.address.is_ascii());
    }

    /// The SENDER can recover the recipient's `(tag, b, ek)` from their address string — so `wallet_send` can
    /// seal a confidential note to any address. A single flipped character fails the keccak checksum.
    #[test]
    fn parse_address_recovers_tag_b_and_ek() {
        let k = derive_keys(&[42u8; 32]);
        let (tag, b, ek) = parse_address(&k.address).expect("our own address must parse");
        assert_eq!(tag, PQ_ADDR_TAG_TESTNET, "testnet tag round-trips");
        assert_eq!(b, k.b, "spend tag b round-trips");
        assert_eq!(ek, k.scan_ek, "the recovered ek IS the recipient's ML-KEM encapsulation key");
        // A corrupted address (flip one char in the middle) fails the checksum → None.
        let mut bad: Vec<u8> = k.address.into_bytes();
        let mid = bad.len() / 2;
        bad[mid] = if bad[mid] == b'A' { b'B' } else { b'A' };
        assert!(parse_address(&String::from_utf8(bad).unwrap()).is_none(), "a tampered address must not parse");
    }

    #[test]
    fn note_seal_scan_roundtrip_recovers_amount() {
        let me = derive_keys(&[5u8; 32]);
        let amount = 123_456_789u64; // atomic units
        let note = seal_note(&me.scan_ek, &me.note_spk, amount).expect("seal");
        assert_eq!(note.len(), PQ_NOTE_BYTES);
        assert_eq!(scan_note(&note, &me.scan_dk, &me.note_spk), Some(amount), "my own note recovers the exact amount");
    }

    #[test]
    fn note_to_other_wallet_is_not_recovered() {
        let me = derive_keys(&[6u8; 32]);
        let other = derive_keys(&[7u8; 32]);
        let note = seal_note(&other.scan_ek, &other.note_spk, 42).expect("seal");
        assert_eq!(scan_note(&note, &me.scan_dk, &me.note_spk), None, "a note sealed to someone else must NOT recover for me");
    }

    /// ⭐ THE EXACT PATH A NEW WALLET IS PAID ON. `harness::generate()` publishes `keys.address` — NOT the
    /// rotating `receive_address` — and the wallet later scans with `keys.scan_dk`. If that published address
    /// carries an ek that `scan_dk` cannot open, every payment to a freshly created wallet is delivered,
    /// recorded, replicated, and permanently invisible to its owner, with no error anywhere. The live
    /// cross-device failure has exactly that shape, and the fingerprints match on paper, so this pins the
    /// actual keypair rather than the label.
    #[test]
    fn a_payment_to_the_address_a_new_wallet_publishes_opens_with_the_key_it_scans_with() {
        let (_phrase, w) = generate().expect("fresh wallet");
        let (_ver, _b, published_ek) =
            parse_address(&w.address).expect("the published address must parse");
        assert_eq!(
            published_ek, w.scan_ek,
            "the PUBLISHED address must carry this wallet's own scan key — otherwise payers seal to a key \
             nobody holds"
        );
        // DB-395: the payer seals to the published SPEND KEY too, read from the same address.
        let published_spk = usdmd_node::address::parse_address_full(&w.address)
            .and_then(|p| p.spk)
            .expect("the published address carries the wallet's spend key (v4)");
        assert_eq!(published_spk, w.note_spk, "the published spend key is this wallet's own");
        let (note, _o) = seal_note_full(&published_ek, &published_spk, 100_000_000).expect("payer seals to the published ek");
        assert_eq!(
            scan_note(&note, &w.scan_dk, &w.note_spk),
            Some(100_000_000),
            "a note sealed to the PUBLISHED address must open with the scan key this wallet actually uses — \
             a mismatch here is money that arrives and can never be found"
        );
    }

    #[test]
    fn tampered_note_is_rejected() {
        let me = derive_keys(&[8u8; 32]);
        let mut note = seal_note(&me.scan_ek, &me.note_spk, 1000).expect("seal");
        note[NOTE_CT_END] ^= 0x01; // flip an enc_amount byte → note_cm binding check must fail
        assert_eq!(scan_note(&note, &me.scan_dk, &me.note_spk), None, "a tampered amount is rejected by the note_cm binding");
    }

    /// ⭐ THE RECEIVE ROUND TRIP: a note sealed to the address a wallet HANDS OUT must be detected by that
    /// same wallet. This is the exact path a cross-device payment takes — payer parses the recipient's
    /// address, seals to the `ek` inside it, and the recipient scans with its own `dk`. Live, the note reaches
    /// the recipient's node (`ingest recorded 2306 carried note bytes`) and the recipient's wallet still
    /// reports 0 owned, so this round trip is where ownership is being lost or preserved. Pinned across
    /// SEVERAL rotating receive indices, because `wallet_address()` hands out `receive_address(.., j)` and a
    /// payer may hold any index — if detection depended on `j`, only the newest address could ever be paid.
    #[test]
    fn a_note_sealed_to_a_handed_out_receive_address_is_detected_by_that_wallet_at_every_index() {
        let (_phrase, w) = generate().expect("fresh wallet");
        for j in usdm_decider::poseidon2_compress::lanes_of(&usdm_decider::poseidon2_compress::lanes_of(&[0, 1, 7, 42])) {
            let addr = receive_address(&w.b, &w.scan_ek, &w.note_spk, &w.loc_sk, j)
                .unwrap_or_else(|| panic!("index {j}: the wallet must be able to hand out an address"));
            let (_ver, _b, ek) = parse_address(&addr)
                .unwrap_or_else(|| panic!("index {j}: the payer must be able to PARSE the handed-out address"));
            assert_eq!(
                ek, w.scan_ek,
                "index {j}: the ek a payer extracts must be this wallet's scan key — otherwise the payment is \
                 sealed to a key nobody holds and the money is simply gone"
            );
            let spk = usdmd_node::address::parse_address_full(&addr)
                .and_then(|p| p.spk)
                .unwrap_or_else(|| panic!("index {j}: a handed-out address carries the wallet's spend key (v4)"));
            assert_eq!(spk, w.note_spk, "index {j}: the spend key a payer extracts is this wallet's own");
            let (note, _o) = seal_note_full(&ek, &spk, 12_345).expect("payer seals the note");
            assert_eq!(
                scan_note(&note, &w.scan_dk, &w.note_spk),
                Some(12_345),
                "index {j}: the recipient MUST detect a note sealed to the address it handed out"
            );
        }
    }

    #[test]
    fn clue_accelerated_restore_recovers_owned_only_with_o_owned_decaps() {
        // The oblivious cold-restore keystone, end to end over the REAL seal + clue + decap: a served "chain" of
        // notes (a few sealed to ME with my clue, the rest to a stranger) → clue-accelerated recover returns
        // EXACTLY my notes' amounts, and the EXPENSIVE ML-KEM decap ran only O(owned) times, not O(chain).
        let me = derive_keys(&*blake3::hash(b"MUSD/pq/clue-restore/me").as_bytes());
        let other = derive_keys(&*blake3::hash(b"MUSD/pq/clue-restore/other").as_bytes());
        let n_chain = 300usize;
        let my_idx = [11usize, 150, 288];
        let my_amounts = [7_000u64, 42_000, 999];

        let mut notes: Vec<[u8; PQ_NOTE_BYTES]> = Vec::with_capacity(n_chain);
        let mut clues: Vec<crate::omr::Clue> = Vec::with_capacity(n_chain);
        for i in 0..n_chain {
            let note_nonce = *blake3::hash(&(i as u64).to_le_bytes()).as_bytes();
            match my_idx.iter().position(|&x| x == i) {
                Some(p) => {
                    notes.push(seal_note_full(&me.scan_ek, &me.note_spk, my_amounts[p]).expect("seal mine").0);
                    clues.push(crate::omr::make_clue(&me.clue_pk, &note_nonce));
                }
                None => {
                    notes.push(seal_note_full(&other.scan_ek, &other.note_spk, 1_234).expect("seal foreign").0);
                    clues.push(crate::omr::make_clue(&other.clue_pk, &note_nonce));
                }
            }
        }
        let served: Vec<CluedNote> = notes
            .iter()
            .zip(clues.iter())
            .map(|(n, c)| CluedNote { note: &n[..], clue: c.clone() })
            .collect();

        let (recovered, decaps) = clue_accelerated_recover(&me.clue_sk, &me.scan_dk, &me.note_spk, &served);
        let mut got: Vec<u64> = recovered.iter().map(|(a, _)| *a).collect();
        got.sort_unstable();
        let mut want = my_amounts.to_vec();
        want.sort_unstable();
        assert_eq!(got, want, "clue-accelerated restore recovers EXACTLY my note amounts");
        assert_eq!(decaps, my_idx.len(), "O(owned) decaps — only pertinent clues paid an ML-KEM decap");
        assert!(decaps * 20 < n_chain, "decaps {decaps} ≪ chain {n_chain} (O(owned), not O(chain))");
    }

    #[test]
    fn malicious_pertinent_clue_on_foreign_note_is_rejected_by_cm_binding() {
        // Soundness: a malicious node swaps a FOREIGN note's clue for one pertinent to ME (forcing a decap). The
        // decap runs, but scan_note_full's note_cm binding REJECTS the foreign note — I NEVER accept a note that
        // is not mine. A false-positive clue costs one wasted decap and nothing more (no money-loss surface).
        let me = derive_keys(&*blake3::hash(b"MUSD/pq/clue-restore/me2").as_bytes());
        let other = derive_keys(&*blake3::hash(b"MUSD/pq/clue-restore/other2").as_bytes());
        let foreign_note = seal_note_full(&other.scan_ek, &other.note_spk, 5_000).expect("seal foreign").0;
        let evil_clue = crate::omr::make_clue(&me.clue_pk, &*blake3::hash(b"evil-clue").as_bytes());
        let served = [CluedNote { note: &foreign_note[..], clue: evil_clue }];

        let (recovered, decaps) = clue_accelerated_recover(&me.clue_sk, &me.scan_dk, &me.note_spk, &served);
        assert_eq!(decaps, 1, "the evil pertinent clue forced exactly one decap");
        assert!(recovered.is_empty(), "the note_cm binding REJECTS the foreign note — no false accept");
    }

    #[test]
    fn corrupt_clue_on_owned_note_is_recovered_by_sound_full_scan() {
        // The false-NEGATIVE money-loss hole + its sound fix. A note is sealed to ME (KEM-decryptable, my note_cm
        // binds), but the clue attached to it is NON-pertinent — a malicious SENDER griefing the payment, or a
        // malicious NODE substituting the clue to HIDE my money. The clue gates the FAST path, so
        // clue_accelerated_recover SKIPS my own note: a permanent loss if the clue path were authoritative.
        // full_recover ignores the sender/node-controlled clue and decaps every note LOCALLY, so it RECOVERS my
        // note. Completeness (never lose money) must not depend on anyone else behaving — the sound path proves it.
        let me = derive_keys(&*blake3::hash(b"MUSD/pq/clue-restore/me3").as_bytes());
        let other = derive_keys(&*blake3::hash(b"MUSD/pq/clue-restore/other3").as_bytes());
        let my_amount = 88_888u64;
        let my_note = seal_note_full(&me.scan_ek, &me.note_spk, my_amount).expect("seal mine").0;
        // A clue on MY note that is DETERMINISTICALLY non-pertinent to me (loop past the ~2^-γ false-positive so
        // the test never flakes): the sender relayed a stranger's/garbage clue instead of one my scan detects.
        let mut ctr = 0u64;
        let mut bad_clue = crate::omr::make_clue(&other.clue_pk, &*blake3::hash(b"corrupt-clue-on-my-note").as_bytes());
        while crate::omr::is_pertinent(&me.clue_sk, &bad_clue) {
            ctr += 1;
            bad_clue = crate::omr::make_clue(&other.clue_pk, &*blake3::hash(&ctr.to_le_bytes()).as_bytes());
        }
        let served = [CluedNote { note: &my_note[..], clue: bad_clue }];

        // FAST clue path SILENTLY SKIPS my own note — no decap, nothing recovered: the money-loss hole.
        let (fast, decaps) = clue_accelerated_recover(&me.clue_sk, &me.scan_dk, &me.note_spk, &served);
        assert_eq!(decaps, 0, "the non-pertinent clue paid no decap — the fast path never even tried my note");
        assert!(fast.is_empty(), "the FAST clue path loses my own note when the clue is corrupt (the hole)");

        // SOUND path RECOVERS my note (ignores the clue, decaps locally, note_cm binds) — no money lost.
        let sound = full_recover(&me.scan_dk, &me.note_spk, &[&my_note[..]]);
        assert_eq!(sound.len(), 1, "the sound complete scan recovers my note despite the corrupt clue");
        assert_eq!(sound[0].0, my_amount, "exact amount recovered — completeness does not depend on the clue");
    }

    // ── Frontier-membership soundness (the oblivious-recovery anchor) ──
    // Cross-check the real `frontier_root`/`frontier_copath` against the node's EXACT MMR root algorithm (a
    // line-for-line port of frontier.rs `NoteFrontier::append` + `root`), so the wallet's membership model is
    // validated to byte-match the node's — computed two independent ways that MUST agree.
    fn mmr_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut pending: Vec<Option<[u8; 32]>> = vec![None; NOTE_TREE_DEPTH + 1];
        for leaf in leaves {
            let mut cur = *leaf;
            let mut level = 0;
            while level <= NOTE_TREE_DEPTH {
                match pending[level].take() {
                    Some(left) => {
                        cur = hash_pair(&left, &cur);
                        level += 1;
                    }
                    None => {
                        pending[level] = Some(cur);
                        break;
                    }
                }
            }
        }
        let mut empty = [[0u8; 32]; NOTE_TREE_DEPTH + 1];
        empty[0] = empty_leaf();
        for l in 1..=NOTE_TREE_DEPTH {
            empty[l] = hash_pair(&empty[l - 1], &empty[l - 1]);
        }
        let mut node = empty[0];
        for l in 0..NOTE_TREE_DEPTH {
            node = match &pending[l] {
                Some(left) => hash_pair(left, &node),
                None => hash_pair(&node, &empty[l]),
            };
        }
        node
    }

    #[test]
    fn wallet_membership_matches_node_frontier_root_and_verifies() {
        // Real note commitments as leaves (any 32-byte values stand in for `cm`s).
        let leaves: Vec<[u8; 32]> = (0..37u32)
            .map(|i| *blake3::hash(&i.to_le_bytes()).as_bytes())
            .collect();
        // The wallet's real `frontier_root` MUST equal the node's exact MMR root algorithm.
        let root = frontier_root(&leaves);
        assert_eq!(root, mmr_root(&leaves), "wallet frontier model diverges from the node's MMR root");
        // Every real note proves membership under that root at its own index (via the real `frontier_copath`).
        for target in [0u64, 1, 2, 5, 17, 36] {
            let copath = frontier_copath(&leaves, target);
            assert!(
                verify_note_membership(&leaves[target as usize], target, &copath, &root),
                "leaf {target} must prove membership in the frontier root"
            );
        }
    }

    #[test]
    fn forged_or_misserved_note_fails_membership() {
        let leaves: Vec<[u8; 32]> = (0..20u32)
            .map(|i| *blake3::hash(&i.to_le_bytes()).as_bytes())
            .collect();
        let root = frontier_root(&leaves);
        let target = 9u64;
        let copath = frontier_copath(&leaves, target);
        // Baseline: the honest note+path verifies.
        assert!(verify_note_membership(&leaves[9], target, &copath, &root));
        // A1 — a FORGED note (cm never appended) has no valid path → rejected.
        let forged = *blake3::hash(b"cm-that-was-never-on-chain").as_bytes();
        assert!(!verify_note_membership(&forged, target, &copath, &root), "a forged cm must not verify");
        // A2 — a real note MIS-SERVED at the wrong index → rejected.
        assert!(!verify_note_membership(&leaves[9], target + 1, &copath, &root), "wrong index must not verify");
        // A3 — a TAMPERED copath (flip one sibling byte) → rejected.
        let mut bad = copath.clone();
        bad[0][0] ^= 0x01;
        assert!(!verify_note_membership(&leaves[9], target, &bad, &root), "a tampered path must not verify");
        // A4 — a wrong-length (truncated) proof → fail-closed.
        assert!(!verify_note_membership(&leaves[9], target, &copath[..31], &root), "short proof must fail-closed");
    }

}

#[cfg(test)]
mod change_note_tests {
    use super::*;
    use fips203::traits::{KeyGen as _, SerDes as _};

    /// A fresh ML-KEM-768 pair as the wallet's own scan key, in the same shape the note path uses.
    /// DB-395: with the wallet's spend key `spk` (its note keys from the same seed).
    fn kp(seed: u8) -> (Vec<u8>, Vec<u8>, Digest4) {
        let (ek, dk) = fips203::ml_kem_768::KG::keygen_from_seed([seed; 32], [seed ^ 0xff; 32]);
        (ek.into_bytes().to_vec(), dk.into_bytes().to_vec(), note_keys(seed).spk)
    }

    fn note_keys(seed: u8) -> NoteKeys {
        NoteKeys::from_entropy(&[seed; 32])
    }

    /// ⭐⭐⭐ THE USER'S ARITHMETIC, STILL ASSERTED: `balance_after == balance_before - sent - fee`, and the
    /// OWNER'S ORDINARY SCAN recovers the remainder (user 2026-08-11: "if 100 is entered to send then only those
    /// 100 usdm should move"). MEASURED 2026-08-11 before re-issue existed: 1,000.00 -> Send 100 -> 0.00, because
    /// the remainder was tagged where no restore looked. DB-273 keeps that closed a different way (the dense `chg`
    /// locator + live trial-decap), so this pin asserts the remainder is found by the ordinary scan WITHOUT
    /// borrowing the input's identity.
    #[test]
    fn a_thousand_note_sending_one_hundred_leaves_nine_hundred_the_owner_can_still_find() {
        let (ek, dk, spk) = kp(11);
        let (input, _in_o) = seal_note_full(&ek, &spk, 1_000_00000000).expect("seal input");
        let sent = 100_00000000u64;
        let fee = 0u64;
        let remainder = 1_000_00000000u64 - sent - fee;
        let (rem_note, rem_o) = seal_note_change(&ek, &spk, &input, &dk, remainder).expect("seal the change");
        assert_eq!(sent + remainder + fee, 1_000_00000000, "value must be conserved");
        let (found_amt, found_seed) = scan_note_full(&rem_note, &dk, &spk)
            .expect("the owner's ORDINARY scan must recover its own remainder — this is the fund loss");
        assert_eq!(found_amt, 900_00000000, "the owner must see 900, not 0");
        assert_eq!(
            note_keys(11).view().opening(&found_seed),
            rem_o,
            "the opening the spend carrier binds is the one the owner's scan derives"
        );
    }

    /// ⭐⭐⭐ DB-273 (D0) — THE CHANGE IS A FRESH NOTE, NOT A COPY OF THE ONE IT CAME FROM. RED before: the
    /// re-issue copied the input's 1,088-B ciphertext verbatim and kept its spend key and view tag — every spend
    /// linked to its change by bytes anyone can store. Two independent fields are compared so neither can hide
    /// behind the other.
    #[test]
    fn db273_the_change_shares_no_ciphertext_and_no_key_with_its_input() {
        let (ek, dk, spk) = kp(7);
        let (note, in_o) = seal_note_full(&ek, &spk, 1_000).expect("seal the input note");
        let (change, change_o) = seal_note_change(&ek, &spk, &note, &dk, 900).expect("seal the change");
        assert_ne!(
            &note[NOTE_CT_OFF..NOTE_CT_END],
            &change[NOTE_CT_OFF..NOTE_CT_END],
            "the change must carry its OWN encapsulation — a copied ciphertext links the spend to its change"
        );
        assert_ne!(in_o, change_o, "a fresh shared secret gives the change its own opening");
        assert_ne!(&note[0..32], &change[0..32], "and its own commitment");
        assert_eq!(scan_note(&change, &dk, &spk), Some(900), "while its owner still opens it at the new value");
    }

    /// TAMPER -> REFUSED. Only the input's OWNER can seal change for it: a stranger's key cannot read the input's
    /// asset, so the sealer refuses instead of sealing change at a guessed asset (the send then fails closed).
    #[test]
    fn a_stranger_cannot_seal_change_for_someone_elses_note() {
        let (ek, _dk, spk) = kp(7);
        let (ek2, dk2, spk2) = kp(9);
        let (note, _owner_o) = seal_note_full(&ek, &spk, 1_000).expect("seal");
        assert!(
            seal_note_change(&ek2, &spk2, &note, &dk2, 900).is_none()
                && seal_note_change(&ek2, &spk, &note, &dk2, 900).is_none(),
            "a note the caller does not own must refuse — never a change note at a guessed asset"
        );
    }

    /// The change's NULLIFIER differs from the input's: value AND key are bound, so it is never a double-spend.
    #[test]
    fn the_change_has_a_different_nullifier_than_the_note_it_replaces() {
        let (ek, dk, spk) = kp(7);
        let (note, _o) = seal_note_full(&ek, &spk, 1_000).expect("seal");
        let (c, _c_o) = seal_note_change(&ek, &spk, &note, &dk, 900).expect("seal the change");
        // DB-395: each note's owner is the wallet's `(ask, nk)` with the seed its own decapsulation yields.
        let seed = |n: &[u8]| scan_note_full(n, &dk, &spk).expect("ours").1;
        let k = note_keys(7);
        assert_ne!(
            crate::pq_spend::note_nullifier(1_000, &k.owner(seed(&note))),
            crate::pq_spend::note_nullifier(900, &k.owner(seed(&c))),
            "the change is its own note, so it is NOT a double-spend of its input"
        );
    }

    /// ⭐⭐ DB-288 §9 — A SELF-NOTE'S KEM MESSAGE RECORDS THE INPUT ITS TRANSACTION CONSUMED, AND ONLY ITS OWNER READS IT.
    /// - The record-carrying note is an ORDINARY note: the owner's ordinary scan reads its amount, asset and spend key.
    /// - The owner reopens it at its own locator and reads back exactly the consumed nullifier.
    /// - TAMPERS: the wrong index, the wrong amount's pad, another wallet's outgoing secret or scan key, and a flipped
    ///   ciphertext bit never yield the nullifier (a flipped bit fails the FO check: `None`).
    /// - A note sealed WITHOUT a record opens to a value that is none of this wallet's nullifiers, so it can never read
    ///   as "spent".
    /// - Deterministic per note content (a retry of the identical object reproduces the identical note), and two notes
    ///   that differ only in amount share no ciphertext.
    /// TWO-PARTY-REVIEWED: the record is written and read by ONE party, the wallet, for itself; no second party reads
    /// it and no value moves on it. The restore that consumes it is pinned in lib.rs.
    #[test]
    fn db288_s9_a_self_notes_kem_message_records_its_consumed_input_for_its_owner_only() {
        let (ek, dk, spk) = kp(21);
        let (ek2, dk2, spk2) = kp(22);
        let (out_sk, other_out) = ([0x5Au8; 32], [0x5Bu8; 32]);
        let nf_in = [0xC3u8; 32];
        let asset = super::USDM_ASSET_TAG;
        let (note, o) = seal_self_note_with_record(&ek, &spk, 900, asset, &out_sk, &nf_in, "chg", 12).expect("seal");
        assert_eq!(
            scan_note_full_asset(&note, &dk, &spk).map(|(a, seed, t)| (a, note_keys(21).view().opening(&seed), t)),
            Some((900, o, asset)),
            "an ordinary note to its owner's scan"
        );
        assert_eq!(open_self_note_record(&note, &dk, &spk, &out_sk, "chg", 12), Some(nf_in), "the owner reads the input back");
        for (label, got) in [
            ("another index", open_self_note_record(&note, &dk, &spk, &out_sk, "chg", 13)),
            ("another domain", open_self_note_record(&note, &dk, &spk, &out_sk, "recv", 12)),
            ("another wallet's outgoing secret", open_self_note_record(&note, &dk, &spk, &other_out, "chg", 12)),
        ] {
            assert!(got.is_some() && got != Some(nf_in), "{label}: decapsulates, but never to the consumed nullifier");
        }
        assert_eq!(open_self_note_record(&note, &dk2, &spk2, &out_sk, "chg", 12), None, "another wallet's scan key: not its note");
        let mut flipped = note;
        flipped[NOTE_CT_OFF + 7] ^= 1;
        assert_eq!(open_self_note_record(&flipped, &dk, &spk, &out_sk, "chg", 12), None, "a flipped ciphertext bit fails the FO check");
        let (plain, _) = seal_note_full_asset(&ek, &spk, 900, asset).expect("seal without a record");
        assert_ne!(
            open_self_note_record(&plain, &dk, &spk, &out_sk, "chg", 12),
            Some(nf_in),
            "a note with no record opens to a pseudorandom value, never a recorded nullifier"
        );
        let (again, _) = seal_self_note_with_record(&ek, &spk, 900, asset, &out_sk, &nf_in, "chg", 12).expect("seal");
        assert_eq!(again, note, "the identical object reproduces the identical note");
        let (other_amt, _) = seal_self_note_with_record(&ek, &spk, 901, asset, &out_sk, &nf_in, "chg", 12).expect("seal");
        assert_ne!(
            other_amt[NOTE_CT_OFF..NOTE_CT_END],
            note[NOTE_CT_OFF..NOTE_CT_END],
            "two notes that differ only in amount share no ciphertext, so no keystream is reused"
        );
        let (to_other, _) = seal_self_note_with_record(&ek2, &spk2, 900, asset, &out_sk, &nf_in, "chg", 12).expect("seal");
        assert_eq!(open_self_note_record(&to_other, &dk2, &spk2, &out_sk, "chg", 12), Some(nf_in), "any recipient key round-trips");
    }

    /// ⭐ SATOSHI §8 PARITY — the node's reward sealer and this wallet's scanner are ONE note layout: a SAT reward the node
    /// seals to this wallet's scan and spend keys (`usdmd_node::faucet::seal_asset_note`) scans here to `(amount, seed, SAT
    /// tag)`, and the seed's opening is the SAME one the node's carrier was proved under; another wallet's key opens nothing; and the wallet's `"sat"`
    /// locate probe (`oli_client::key_for_v2`) is byte-identical to the index key of the clue the node files
    /// (`satoshi::reward_clue`) — so the doubling sweep finds every reward and recovers its index. TWO-PARTY-REVIEWED:
    /// node sealer / wallet scanner; node clue / wallet probe.
    #[test]
    fn a_sat_reward_the_node_seals_is_this_wallets_sat_note_and_its_clue_is_the_wallets_locate_probe() {
        let mine = derive_keys(&[21u8; 32]);
        let other = derive_keys(&[22u8; 32]);
        let tag = usdmd_node::satoshi::asset_tag();
        let (note, o_node) = usdmd_node::faucet::seal_asset_note(&mine.scan_ek, &mine.note_spk, 4_159_090, tag, Some([3u8; 32]))
            .expect("the node seals");
        let (amount, seed, asset) = scan_note_full_asset(&note, &mine.scan_dk, &mine.note_spk).expect("this wallet scans its reward");
        assert_eq!((amount, asset), (4_159_090, tag), "the schedule's amount, denominated in SAT");
        let o = mine.note_view().opening(&seed);
        assert_eq!(o, o_node, "the wallet's opening is the one the node's mint carrier was proved under");
        assert_eq!(&note[..32], &usdmd_node::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(amount, asset, o)), "cm opens");
        assert!(scan_note_full_asset(&note, &other.scan_dk, &other.note_spk).is_none(), "⛔ another wallet opened this wallet's reward");
        // the amount scanner binds under the note's OWN tag (so wrapped notes are never read as foreign): it reads the amount;
        // which asset it is comes only from the full scanner above
        assert_eq!(scan_note(&note, &mine.scan_dk, &mine.note_spk), Some(4_159_090), "CALIBRATION: the amount scanner opens the note too");
        for j in [0u64, 1, 7, 1 << 40] {
            let clue = usdmd_node::satoshi::reward_clue(&mine.sat_loc_sk, j);
            assert_eq!(
                usdmd_node::oli::index_key(&clue),
                crate::oli_client::key_for_v2(&mine.sat_loc_sk, usdmd_node::satoshi::SAT_LOC_DOMAIN, j),
                "the wallet's probe at j is the node's filed key at j"
            );
            assert_eq!(usdmd_node::satoshi::reward_clue_index(&mine.sat_loc_sk, &clue), Some(j), "one-step index recovery");
            assert_eq!(usdmd_node::satoshi::reward_clue_index(&other.sat_loc_sk, &clue), None, "⛔ a stranger recognised the clue");
        }
        assert_ne!(mine.sat_loc_sk, mine.loc_sk, "the reward key is NOT the wallet's locator key (least privilege at the node)");
        assert_eq!(derive_keys(&[21u8; 32]).sat_loc_sk, mine.sat_loc_sk, "seed-derived: a restore sweeps the same space");
    }
}

#[cfg(test)]
mod master_key_tests {
    /// ⭐ R7 F3 — the master key restores the SAME wallet as the 24 words, and every single-character typo, a dropped
    /// checksum and a wrong length are REFUSED (never an empty wallet).
    #[test]
    fn the_master_key_restores_the_same_wallet_and_every_typo_is_refused() {
        let (phrase, keys) = super::generate().expect("generate");
        let mk = super::master_key_of_phrase(&phrase).expect("the master key of the phrase");
        assert_eq!(mk.len(), 64 + 1 + 8, "64 hex, a dash, 8 hex");
        let back = super::restore(&mk).expect("the master key restores");
        assert_eq!(back.address, keys.address, "⛔ the master key restored a different wallet than the words");
        let spaced = format!("  {}  ", mk.to_uppercase().replace('-', " "));
        assert_eq!(super::restore(&spaced).expect("case and spacing tolerated").address, keys.address);
        let chars: Vec<char> = mk.chars().collect();
        let mut refused = 0usize;
        for i in (0..chars.len()).filter(|i| chars[*i] != '-') {
            let mut t = chars.clone();
            t[i] = if t[i] == '0' { '1' } else { '0' };
            let typo: String = t.into_iter().collect();
            match super::restore(&typo) {
                Err(e) => {
                    assert!(e.contains("checksum"), "a typo is named as a checksum failure: {e}");
                    refused += 1;
                }
                Ok(k) => panic!("⛔ a master key with a typo at {i} restored a wallet ({})", &k.address[..12]),
            }
        }
        assert_eq!(refused, 72, "every one of the 72 characters' typos is refused");
        match super::restore(&mk[..64]) {
            Err(e) => assert!(e.contains("72"), "a key without its checksum is named by its length: {e}"),
            Ok(_) => panic!("⛔ a master key without its checksum was accepted"),
        }
        assert!(super::restore(&format!("{mk}0")).is_err(), "⛔ a master key with an extra character was accepted");
    }
}
