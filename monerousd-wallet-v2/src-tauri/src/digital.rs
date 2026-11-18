// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ A DOWNLOAD SOLD FOR ITS KEY (docs/GOODS-AND-SERVICES-LAYER-SPEC-20261109.md §3.3: downloads, licenses, tickets,
//! codes). The seller seals a file under a key and locks the buyer's money with a lock only that key opens; the spend
//! that pays the seller publishes the key to the buyer (`usdm_decider`, THE DELIVERY LOCK). Being paid IS handing the
//! key over, so there is no code to confirm and nothing to dispute.
//!
//! WHAT THE BUYER'S WALLET CHECKS BEFORE IT LOCKS ANY MONEY: it holds the whole sealed content, and a proof the seller
//! made once for the listing (`usdm_decider::whir_rec_block::content_gate`) that the key behind the lock opens that
//! sealed content, block by block, to the content the offer names by its root. The buyer's wallet builds the vault
//! itself under the lock the offer states. A sale adds no proof.
//!
//! THE BUNDLE a seller stores on the Veil under its root alone (`veil_site::store`) and a buyer reads by that root:
//!
//! ```text
//! "MUDSALE1" ‖ seller's address key ‖ byte length ‖ block count ‖ every sealed block ‖ every leaf ‖ the proof
//!            ‖ for a large file: its length, its ID (the BLAKE3 hash of the file) and the root of its sealed bytes
//! ```
//!
//! A FILE UP TO [`DIRECT_MAX`] BYTES is the sealed content itself: every byte is proven before payment.
//! A LARGER FILE is sealed with a file key under an ordinary stream cipher and stored as bytes of its own; what is
//! sold and proven is a short RECORD holding that file key and the file's ID. The key the buyer pays for is proven to
//! open the record. That the file key opens the large file to its ID is checked by the buyer's wallet AFTER payment,
//! and the wallet says so in plain words before the buyer confirms: for a large file the ID is what the buyer trusts.
//!
//! Nothing is stored by either wallet. The seller's key and salt are functions of its own secret and the offer's
//! nonce, so the offer link is all it needs to deliver. The buyer's download waits in memory until it is saved; a
//! buyer's wallet that was closed in between reads the key from the seller's letter and the bundle from the Veil again.

use super::*;
use usdm_decider::whir_rec_block::{
    content_blocks, content_bytes, content_leaf, content_root, delivery_locks, open_block, prove_content, seal_block, verify_content, ContentRow, ContentStatement,
    ListingSalt, VaultSecret, CONTENT_BLOCK_BYTES, CONTENT_PROOF_MAX_ROWS,
};

const BUNDLE_MAGIC: &[u8; 8] = b"MUDSALE1";
/// The first byte of sealed content: the file itself, or a large file's record.
const KIND_FILE: u8 = 1;
const KIND_RECORD: u8 = 2;
/// The most bytes of a file that are sealed and proven whole (the proof's table, less the name's room).
// PRODUCTION-SCALE-REVIEWED: the size at which a file is sold through a record instead of being proven byte for byte
// (one content proof's table, 30,720 bytes, less 258 for the name); it limits no file's size.
pub const DIRECT_MAX: usize = CONTENT_PROOF_MAX_ROWS * CONTENT_BLOCK_BYTES - 258;
/// The most bytes of a file this wallet seals at all: it is held in memory while it is sealed and stored.
// PRODUCTION-SCALE-REVIEWED: a bound on one file held in this wallet's memory while it is listed or opened (64 MiB),
// the same in production; a larger file is told so in words.
pub const FILE_MAX: usize = 64 << 20;

/// What a listing states about its download, as the offer link carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    /// The content's root, 32 bytes of hex.
    pub root: String,
    /// The listing's delivery lock, 32 bytes of hex.
    pub lock: String,
    /// The listing's salt, 16 bytes of hex.
    pub salt: String,
    /// The Veil root the bundle is read by, 32 bytes of hex.
    pub bundle: String,
}

/// A large file's public facts, carried in the bundle and repeated inside the sealed record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LargeFile {
    pub len: u64,
    /// The BLAKE3 hash of the file: its ID.
    pub id: [u8; 32],
    /// The Veil root of its sealed bytes.
    pub sealed_root: [u8; 32],
}

/// A bundle a buyer's wallet checked against an offer.
#[derive(Clone, Debug)]
pub struct Checked {
    pub seller_spk: Digest4,
    pub locks: [usdm_decider::whir_rec_block::VaultLock; 2],
    pub salt: ListingSalt,
    pub len: u64,
    pub sealed: Vec<Digest4>,
    pub leaves: Vec<Digest4>,
    pub large: Option<LargeFile>,
}

fn digest_hex(d: &Digest4) -> String {
    hex::encode(usdmd_node::spend_frontier::leaf_to_cm_bytes(*d))
}

fn digest_of(bytes: &[u8]) -> Option<Digest4> {
    usdmd_node::spend_frontier::cm_bytes_to_root(&<[u8; 32]>::try_from(bytes).ok()?)
}

/// The listing's key and salt: functions of this wallet's secret and the offer's nonce, never stored.
pub fn listing_secrets(nonce: &str) -> Result<(VaultSecret, ListingSalt), String> {
    Ok((vault_ops::derived_lanes("content-key", nonce)?, vault_ops::derived_lanes("content-salt", nonce)?))
}

fn file_key(nonce: &str) -> Result<[u8; 32], String> {
    let lanes = vault_ops::derived_lanes("file-key", nonce)?;
    let mut h = blake3::Hasher::new_derive_key("MonerousD 2026-11-10 sold file key v1");
    for l in lanes {
        h.update(&l.to_le_bytes());
    }
    Ok(*h.finalize().as_bytes())
}

/// A large file under its file key: each byte with a keystream byte (BLAKE3 in its extendable-output mode, keyed).
/// The same call seals and opens.
fn stream(key: &[u8; 32], bytes: &[u8]) -> Vec<u8> {
    let mut reader = blake3::Hasher::new_keyed(key).update(b"MonerousD sold file stream v1").finalize_xof();
    let mut out = vec![0u8; bytes.len()];
    reader.fill(&mut out);
    for (o, b) in out.iter_mut().zip(bytes) {
        *o ^= b;
    }
    out
}

fn named(kind: u8, name: &str, rest: &[u8]) -> Vec<u8> {
    let name: String = name.chars().filter(|c| !c.is_control() && !matches!(c, '/' | '\\')).take(120).collect();
    let name = if name.trim().is_empty() { "download".to_string() } else { name };
    let mut out = Vec::with_capacity(2 + name.len() + rest.len());
    out.push(kind);
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(rest);
    out
}

fn unnamed(content: &[u8]) -> Option<(u8, String, &[u8])> {
    let n = usize::from(*content.get(1)?);
    let name = std::str::from_utf8(content.get(2..2 + n)?).ok()?;
    if name.is_empty() || name.chars().any(|c| c.is_control() || matches!(c, '/' | '\\')) {
        return None;
    }
    Some((content[0], name.to_string(), &content[2 + n..]))
}

/// SELLER: seal the file `name` holding `bytes` for the listing with `nonce`. Returns the bundle to store, the sealed
/// bytes of a large file to store beside it (`None` for a file sealed whole), and what the offer states. `store_large`
/// stores a large file's sealed bytes and returns the root they are read by.
pub fn seal_listing(nonce: &str, name: &str, bytes: &[u8], store_large: &dyn Fn(&[u8]) -> Result<[u8; 32], String>) -> Result<(Vec<u8>, [String; 3]), String> {
    if bytes.is_empty() {
        return Err("the file is empty".to_string());
    }
    if bytes.len() > FILE_MAX {
        return Err("that file is larger than this wallet can list (64 MB)".to_string());
    }
    let (key, salt) = listing_secrets(nonce)?;
    let seller_spk = own_note_keys()?.spk;
    let (content, large) = if bytes.len() <= DIRECT_MAX {
        (named(KIND_FILE, name, bytes), None)
    } else {
        let fk = file_key(nonce)?;
        let sealed_root = store_large(&stream(&fk, bytes))?;
        let large = LargeFile { len: bytes.len() as u64, id: *blake3::hash(bytes).as_bytes(), sealed_root };
        let mut record = fk.to_vec();
        record.extend_from_slice(&large.len.to_le_bytes());
        record.extend_from_slice(&large.id);
        record.extend_from_slice(&large.sealed_root);
        (named(KIND_RECORD, name, &record), Some(large))
    };
    let blocks = content_blocks(&content).filter(|b| b.len() <= CONTENT_PROOF_MAX_ROWS).ok_or_else(|| "the file could not be sealed".to_string())?;
    let leaves: Vec<Digest4> = blocks.iter().enumerate().map(|(j, b)| content_leaf(j as u64, b)).collect();
    let root = content_root(&leaves, content.len() as u64);
    let sealed: Vec<Digest4> = blocks.iter().enumerate().map(|(j, b)| seal_block(b, &key, j as u64)).collect();
    let locks = delivery_locks(&seller_spk, &key, &salt);
    let st = ContentStatement {
        seller_spk,
        salt,
        locks,
        rows: (0..blocks.len()).map(|j| ContentRow { index: j as u64, sealed: sealed[j], leaf: leaves[j] }).collect(),
        context: root,
    };
    let proof = prove_content(&st, &key).ok_or_else(|| "the content proof could not be made".to_string())?;
    let mut out = Vec::with_capacity(64 + blocks.len() * 64 + proof.len() + 80);
    out.extend_from_slice(BUNDLE_MAGIC);
    out.extend_from_slice(&usdmd_node::spend_frontier::leaf_to_cm_bytes(seller_spk));
    out.extend_from_slice(&(content.len() as u64).to_le_bytes());
    out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
    for block in &sealed {
        for lane in block {
            out.extend_from_slice(&(*lane as u32).to_le_bytes());
        }
    }
    for leaf in &leaves {
        out.extend_from_slice(&usdmd_node::spend_frontier::leaf_to_cm_bytes(*leaf));
    }
    out.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    out.extend_from_slice(&proof);
    if let Some(l) = &large {
        out.extend_from_slice(&l.len.to_le_bytes());
        out.extend_from_slice(&l.id);
        out.extend_from_slice(&l.sealed_root);
    }
    Ok((out, [digest_hex(&root), vault_ops::delivery_lock_hex(&locks), vault_ops::lanes_hex(&salt)]))
}

/// BUYER: is `bundle` the sealed content this offer names, with a proof that the key behind the offer's lock opens
/// it? Everything is checked here, before any money is locked: the leaves against the offer's root, the proof against
/// the offer's lock and salt, and every sealed lane as a field value.
pub fn check_bundle(bundle: &[u8], l: &Listing) -> Result<Checked, String> {
    let bad = || "this download's sealed content is not what the offer names — nothing was sent".to_string();
    let mut at = bundle.strip_prefix(BUNDLE_MAGIC).ok_or_else(bad)?;
    let mut take = |n: usize| -> Result<&[u8], String> {
        let (head, rest) = at.split_at_checked(n).ok_or_else(bad)?;
        at = rest;
        Ok(head)
    };
    let seller_spk = digest_of(take(32)?).ok_or_else(bad)?;
    let len = u64::from_le_bytes(take(8)?.try_into().map_err(|_| bad())?);
    let n = u32::from_le_bytes(take(4)?.try_into().map_err(|_| bad())?) as usize;
    if n == 0 || n > CONTENT_PROOF_MAX_ROWS || usize::try_from(len).ok().map(|l| l.div_ceil(CONTENT_BLOCK_BYTES).max(1)) != Some(n) {
        return Err(bad());
    }
    let sealed: Vec<Digest4> = take(n * 32)?.chunks_exact(32).map(|b| core::array::from_fn(|c| u64::from(u32::from_le_bytes([b[4 * c], b[4 * c + 1], b[4 * c + 2], b[4 * c + 3]])))).collect();
    let leaves: Vec<Digest4> = take(n * 32)?.chunks_exact(32).map(digest_of).collect::<Option<Vec<_>>>().ok_or_else(bad)?;
    let proof_len = u32::from_le_bytes(take(4)?.try_into().map_err(|_| bad())?) as usize;
    let proof = take(proof_len)?.to_vec();
    let rest = at;
    let large = match rest.len() {
        0 => None,
        72 => Some(LargeFile { len: u64::from_le_bytes(rest[..8].try_into().map_err(|_| bad())?), id: rest[8..40].try_into().map_err(|_| bad())?, sealed_root: rest[40..].try_into().map_err(|_| bad())? }),
        _ => return Err(bad()),
    };
    let root = hex::decode(&l.root).ok().and_then(|b| digest_of(&b)).ok_or_else(bad)?;
    if content_root(&leaves, len) != root {
        return Err(bad());
    }
    let lock = hex::decode(&l.lock).map_err(|_| bad())?;
    if lock.len() != 32 {
        return Err(bad());
    }
    let locks = [vault_ops::lanes_of_hex(&l.lock[..32]).map_err(|_| bad())?, vault_ops::lanes_of_hex(&l.lock[32..]).map_err(|_| bad())?];
    let salt = vault_ops::lanes_of_hex(&l.salt).map_err(|_| bad())?;
    let st = ContentStatement {
        seller_spk,
        salt,
        locks,
        rows: (0..n).map(|j| ContentRow { index: j as u64, sealed: sealed[j], leaf: leaves[j] }).collect(),
        context: root,
    };
    if !verify_content(&proof, &st) {
        return Err("this download's proof does not check out: the key you would pay for is not shown to open it — nothing was sent".to_string());
    }
    Ok(Checked { seller_spk, locks, salt, len, sealed, leaves, large })
}

/// Is `key` the key of the lock this checked bundle's offer states?
#[must_use]
pub fn key_fits(c: &Checked, key: &VaultSecret) -> bool {
    delivery_locks(&c.seller_spk, key, &c.salt) == c.locks
}

/// BUYER, with the key: the file. For a large file `read_large` reads its sealed bytes by their root. `Err` when the
/// content does not open to what was proven (it cannot, for a key that fits) or a large file is not the file its ID
/// names (the one thing no proof covered).
pub fn open(c: &Checked, key: &VaultSecret, read_large: &dyn Fn(&[u8; 32]) -> Result<Vec<u8>, String>) -> Result<(String, Vec<u8>), String> {
    if !key_fits(c, key) {
        return Err("that is not this download's key".to_string());
    }
    let blocks: Vec<Digest4> = c.sealed.iter().enumerate().map(|(j, s)| open_block(s, key, j as u64)).collect();
    if blocks.iter().enumerate().any(|(j, b)| content_leaf(j as u64, b) != c.leaves[j]) {
        return Err("the key does not open this download to what was proven".to_string());
    }
    let content = content_bytes(&blocks, c.len).ok_or_else(|| "this download's content is malformed".to_string())?;
    let (kind, name, rest) = unnamed(&content).ok_or_else(|| "this download's content is malformed".to_string())?;
    match (kind, &c.large) {
        (KIND_FILE, None) => Ok((name, rest.to_vec())),
        (KIND_RECORD, Some(large)) => {
            if rest.len() != 104 {
                return Err("this download's record is malformed".to_string());
            }
            let fk: [u8; 32] = rest[..32].try_into().map_err(|_| "bad record".to_string())?;
            // the record the key opened names the same file the bundle showed before payment
            if rest[32..40] != large.len.to_le_bytes() || rest[40..72] != large.id || rest[72..] != large.sealed_root {
                return Err("this download's record names another file than the offer showed".to_string());
            }
            let sealed = read_large(&large.sealed_root)?;
            let file = stream(&fk, &sealed);
            if file.len() as u64 != large.len || *blake3::hash(&file).as_bytes() != large.id {
                return Err("the file that arrived is not the file this offer's ID names. The seller was paid for its key; the file itself was not proven before payment, as the offer said.".to_string());
            }
            Ok((name, file))
        }
        _ => Err("this download's content is malformed".to_string()),
    }
}

/// The one sentence a buyer confirms for a download, after its wallet has checked the bundle.
/// ⛔ AUDIT F10 (2026-11-10) — SAID BEFORE THE TAP. The key reaches the buyer by the seller's own spend, which this
/// wallet's node sees only while it runs or within the blocks it still keeps (`block_window::WHOLE_KEEP`), and by the
/// seller's letter. A seller that collects while the buyer's wallet is closed and sends no letter has been paid for a
/// key the buyer never read. Until the key is carried by something the chain keeps for the buyer, the buyer is told.
const KEEP_OPEN: &str = "Keep your wallet open until the file arrives, usually within a minute of paying: if you close it before then, the key can be missed and you would have paid without getting the file.";

pub fn sentence(c: &Checked, who: &str, title: &str, amount: u64, days: &str) -> String {
    let base = format!("Pay ${:.2} to {who} for {}, a download.", atomic_to_usdm(amount), approval_short(title, 60));
    match &c.large {
        None => format!(
            "{base} Your wallet has checked that the key you are paying for opens exactly this file ({} bytes). {KEEP_OPEN} If the seller does not deliver within {days}, the payment returns to you.",
            c.len
        ),
        Some(l) => format!(
            "{base} It is a large file ({:.1} MB, ID {}). Your wallet has checked that the key you are paying for opens the file's key record, and it will check the file against its ID after payment. Before payment only the record is proven: buy a large file only when you trust its ID. {KEEP_OPEN} If the seller does not deliver within {days}, the payment returns to you.",
            l.len as f64 / 1_048_576.0,
            hex::encode(&l.id[..6])
        ),
    }
}

// TWO-PARTY-REVIEWED: these tests are the seller's sealing against the buyer's own check and open, in one process with
// no wallet (the keys are test keys). A seller's wallet and a buyer's wallet on two real nodes, the payment, and the
// key read from the seller's spend are the real-node check `scratchpad/net/goods.py`, step "download".
#[cfg(test)]
mod tests {
    use super::*;

    const KEY: VaultSecret = [0x00C0_FFEE, 0x3F00_0000, 3, 0x1234_5678];
    const SALT: ListingSalt = [0x5A17, 11, 12, 13];

    fn spk() -> Digest4 {
        usdmd_node::spend_frontier::note_leaf_of(blake3::hash(b"a seller").as_bytes())
    }

    /// The bundle and listing a seller with test keys makes for `content` (no wallet is open in a unit test).
    fn listed(content: &[u8], large: Option<&LargeFile>) -> (Vec<u8>, Listing) {
        let blocks = content_blocks(content).expect("fits");
        let leaves: Vec<Digest4> = blocks.iter().enumerate().map(|(j, b)| content_leaf(j as u64, b)).collect();
        let root = content_root(&leaves, content.len() as u64);
        let sealed: Vec<Digest4> = blocks.iter().enumerate().map(|(j, b)| seal_block(b, &KEY, j as u64)).collect();
        let locks = delivery_locks(&spk(), &KEY, &SALT);
        let st = ContentStatement { seller_spk: spk(), salt: SALT, locks, rows: (0..blocks.len()).map(|j| ContentRow { index: j as u64, sealed: sealed[j], leaf: leaves[j] }).collect(), context: root };
        let proof = prove_content(&st, &KEY).expect("proves");
        let mut out = BUNDLE_MAGIC.to_vec();
        out.extend_from_slice(&usdmd_node::spend_frontier::leaf_to_cm_bytes(spk()));
        out.extend_from_slice(&(content.len() as u64).to_le_bytes());
        out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
        for block in &sealed {
            for lane in block {
                out.extend_from_slice(&(*lane as u32).to_le_bytes());
            }
        }
        for leaf in &leaves {
            out.extend_from_slice(&usdmd_node::spend_frontier::leaf_to_cm_bytes(*leaf));
        }
        out.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        out.extend_from_slice(&proof);
        if let Some(l) = large {
            out.extend_from_slice(&l.len.to_le_bytes());
            out.extend_from_slice(&l.id);
            out.extend_from_slice(&l.sealed_root);
        }
        (out, Listing { root: digest_hex(&root), lock: vault_ops::delivery_lock_hex(&locks), salt: vault_ops::lanes_hex(&SALT), bundle: String::new() })
    }

    #[test]
    fn a_buyer_checks_a_download_before_paying_and_opens_it_with_the_key_alone() {
        let file = b"LICENSE-KEY 7Q2M-XK4P-99AZ\nvalid for one seat\n".to_vec();
        let (bundle, listing) = listed(&named(KIND_FILE, "license.txt", &file), None);
        let checked = check_bundle(&bundle, &listing).expect("the buyer's check passes");
        assert!(checked.large.is_none());
        let never = |_: &[u8; 32]| -> Result<Vec<u8>, String> { Err("no large file".to_string()) };
        assert_eq!(open(&checked, &KEY, &never).expect("opens"), ("license.txt".to_string(), file));
        // a key that is not the lock's opens nothing
        let mut other = KEY;
        other[0] ^= 1;
        assert!(!key_fits(&checked, &other) && open(&checked, &other, &never).is_err());
        // THE OFFER NAMES ANOTHER CONTENT, LOCK OR SALT: the same bundle is refused before any money moves
        for (name, lie) in [
            ("root", Listing { root: digest_hex(&spk()), ..listing.clone() }),
            ("lock", Listing { lock: vault_ops::delivery_lock_hex(&delivery_locks(&spk(), &other, &SALT)), ..listing.clone() }),
            ("salt", Listing { salt: vault_ops::lanes_hex(&[1, 2, 3, 4]), ..listing.clone() }),
        ] {
            assert!(check_bundle(&bundle, &lie).is_err(), "⛔ a bundle checked out against another {name}");
        }
        // A BUNDLE ALTERED ANYWHERE is refused: a sealed lane, a leaf, the seller's key, the proof, the length
        for at in [8 + 3, 8 + 32 + 8 + 4 + 5, bundle.len() - 9, 8 + 32 + 2] {
            let mut bent = bundle.clone();
            bent[at] ^= 1;
            assert!(check_bundle(&bent, &listing).is_err(), "⛔ a bundle altered at byte {at} checked out");
        }
        assert!(check_bundle(&bundle[..bundle.len() - 1], &listing).is_err());
        assert!(check_bundle(b"MUDSALE1", &listing).is_err());
        // the sentence says what was checked, in bytes of the content
        let said = sentence(&checked, "@shop", "A license", 500_000_000, "1 day");
        assert!(said.contains("$5.00") && said.contains("opens exactly this file") && !said.contains("large file"));
    }

    #[test]
    fn a_large_file_is_opened_through_its_record_and_a_wrong_file_is_named_as_one() {
        let file: Vec<u8> = (0..200_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        let fk = [0x42u8; 32];
        let sealed_file = stream(&fk, &file);
        assert_eq!(stream(&fk, &sealed_file), file, "the stream opens what it seals");
        assert_ne!(sealed_file[..64], file[..64]);
        let large = LargeFile { len: file.len() as u64, id: *blake3::hash(&file).as_bytes(), sealed_root: [0x77; 32] };
        let mut record = fk.to_vec();
        record.extend_from_slice(&large.len.to_le_bytes());
        record.extend_from_slice(&large.id);
        record.extend_from_slice(&large.sealed_root);
        let (bundle, listing) = listed(&named(KIND_RECORD, "film.mp4", &record), Some(&large));
        let checked = check_bundle(&bundle, &listing).expect("the record's proof checks out");
        assert_eq!(checked.large, Some(large.clone()));
        let said = sentence(&checked, "this seller", "A film", 900_000_000, "2 days");
        assert!(said.contains("large file") && said.contains("only the record is proven"), "the buyer is told what is not proven: {said}");
        // the right sealed bytes open to the file
        let good = |root: &[u8; 32]| -> Result<Vec<u8>, String> {
            assert_eq!(*root, [0x77; 32]);
            Ok(sealed_file.clone())
        };
        assert_eq!(open(&checked, &KEY, &good).expect("opens"), ("film.mp4".to_string(), file.clone()));
        // sealed bytes that are not the file's: named as not the file, never handed over as it
        let mut wrong = sealed_file.clone();
        wrong[1000] ^= 1;
        let bad = |_: &[u8; 32]| -> Result<Vec<u8>, String> { Ok(wrong.clone()) };
        assert!(open(&checked, &KEY, &bad).is_err_and(|e| e.contains("not the file this offer's ID names")));
        // a bundle whose shown ID differs from the record's is refused when the record is opened
        let mut shown_other = bundle.clone();
        let at = shown_other.len() - 40;
        shown_other[at] ^= 1;
        let checked_other = check_bundle(&shown_other, &listing).expect("the proof still covers the record");
        assert!(open(&checked_other, &KEY, &good).is_err_and(|e| e.contains("names another file")));
    }

    #[test]
    fn a_name_cannot_walk_out_of_the_download_folder() {
        assert_eq!(unnamed(&named(KIND_FILE, "../../etc/passwd", b"x")).expect("parses").1, "....etcpasswd");
        assert_eq!(unnamed(&named(KIND_FILE, "  ", b"x")).expect("parses").1, "download");
        let mut raw = vec![KIND_FILE, 4];
        raw.extend_from_slice(b"a/b!");
        assert!(unnamed(&raw).is_none(), "a path separator in a stored name is refused on the way out too");
    }
}
