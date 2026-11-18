// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! **On-chain directory** — the @username + Letter-group handle registry, reconstructed as a deterministic FOLD of
//! the block-carried [`crate::block::Block::dir_set`] rather than a per-node disk cache. This is the post-DA
//! correction to the pre-DA [`crate::names`] design (gossip + a local JSON file): a local file made disk a
//! mini-authority and left first-come to a gossip race, both of which break DA-is-the-ledger / no-local-storage /
//! reconstruct-from-mesh.
//!
//! Every sign-up RIDES A BLOCK. The producer seals its pending [`DirEntry`]s into `dir_set`; the header's
//! `dir_set_root` binds them to the block id; and [`crate::node::Node::apply_dir_set`] re-verifies each ML-DSA
//! signature (over [`dir_register_msg`]) + the first-come / owner-continuity rule on EVERY node, folding the result
//! into this projection. So the resolved directory is a pure function of canonical chain order — identical on every
//! node, reconstructed on restart/DSYNC-join from the mesh, with nothing trusted on disk.
//!
//! RESOLUTION IS A KEYED ONE-READ, NEVER A SCAN. `resolve_name`/`resolve_group` are `HashMap::get` on the hash of
//! the canonical key — the same O(1) indexed-lookup shape [`crate::node::Node::da_ordinal_at_membership_acc`] uses.
//! There is deliberately NO substring search here: scanning every entry would be work that grows with the directory
//! (banned). Discovery is handle-exact (this) + a tag page (a future fixed-size cursored read), never a full scan.
//!
//! Privacy: a @username or a group handle is OPT-IN discovery metadata the owner CHOSE to publish (the same public
//! category as today's @username handle). It names no note, amount, key, or value; ordinary payment privacy is
//! untouched. A "discoverable" group is findable + join-to-read (content stays sealed to members).
use std::collections::HashMap;

/// A username sign-up entry.
pub const KIND_NAME: u8 = 0;
/// A group-handle sign-up entry.
pub const KIND_GROUP: u8 = 1;
/// A PROFILE record — per-identity display customization published by the identity's own key: display
/// name, bio, and the DM-acceptance fee (micro-USDm; 0 = free DMs). Keyed by the OWNER'S ADDRESS (not a
/// claimable handle), so only that wallet can ever write it — first-come is trivially the owner.
/// Telegram-parity surface (profile + paid-DM gate) with zero privacy loss: everything here is data the
/// owner CHOSE to publish, exactly like an @username.
pub const KIND_PROFILE: u8 = 2;

/// ⭐⭐⭐ A USERNAME HANDOVER — what makes a @username a TRADEABLE chain asset rather than a permanent
/// claim.
///
/// ⛔⛔⛔ BEFORE THIS KIND, A USERNAME COULD NEVER CHANGE OWNER. `apply_entry`'s rule is
/// `Some(r) if r.owner != owner => false` — an entry signed by anyone but the recorded owner is refused,
/// always — so the owner was immutable from the moment of first claim. The `DirEntry::pubkey` doc claimed
/// *"only this key may re-point / transfer"*, and only the re-point half was true. A name could be bought
/// and paid for and never actually move.
///
/// ⭐ THE OLD TREE HAD THIS AND GREENFIELD DID NOT CARRY IT FORWARD. Register, swap and gift-transfer were
/// all built, made sound (the `UsernameOwnershipNullifierAir` theft gate) and deployed there; only the
/// REGISTER half survived the move ([[feedback_greenfield_oldtree_parity]]).
///
/// FIELD MEANING FOR THIS KIND (each field's meaning is already per-kind — `name`/`topic` are documented
/// as empty for a username entry):
/// * `key`     — the username being handed over.
/// * `address` — the address it should resolve to after the handover (usually the buyer's).
/// * `name`    — the NEW OWNER'S ID as 64 hex chars: `H(new_pubkey)`, the same `pubkey_id` every node
///               derives for a signer. ⛔ THE ID, NOT THE KEY: the buyer never has to publish their
///               public key to receive a name, and the seller cannot be asked to hold it.
/// * `pubkey` / `sig` — the CURRENT owner's key and signature. The signature covers `name`, so the new
///               owner is bound into the signed message and cannot be substituted in flight.
pub const KIND_NAME_TRANSFER: u8 = 3;

/// ⭐ A COLLECTION (spec `docs/IONSWAP-POOLS-SPEC-20261110.md` §12.6, 2026-11-11) — what a creator's pieces are browsed
/// under in the marketplace. A PAID, SIGNED entry like a group handle (`dir_entry_tx`): a handle unique on the chain,
/// first come, owned by the key that signed it; only that key may change its title, words or cover.
///
/// FIELD MEANING FOR THIS KIND:
/// * `key`     — the handle (canonical: lower case, [`collection_handle_ok`]).
/// * `name`    — the title shown above the pieces (at most [`COLLECTION_TITLE_MAX`] bytes).
/// * `topic`   — the description (at most [`COLLECTION_TEXT_MAX`] bytes).
/// * `pic`     — the blake3 digest of the cover picture, or `None`. The picture's own bytes (PNG, JPEG or WebP, at
///               most [`COLLECTION_COVER_MAX`]) ride the paid object beside the entry and are kept by digest
///               ([`Directory::keep_pic`]); the entry itself only names them.
/// * `address` — empty: a collection routes nothing to anyone.
/// * `pubkey` / `sig` — the owner's key and signature over [`dir_entry_msg`], which covers the cover's digest.
pub const KIND_COLLECTION: u8 = 4;

/// ⭐ AN ASSET'S RECORD (spec §12.6) — the name, kind, creator and picture of a token or an NFT, kept by every node so a
/// wallet, the marketplace and the explorer name and picture an asset from the chain itself, with no card handed over.
///
/// ⛔ WRITTEN BY A CREATION'S OWN FOLD AND BY NOTHING ELSE. It carries no signature: the fold of the asset's
/// `AssetCreateTx` (whose fee burn is bound to these facts and whose picture hashes to the digest the asset's identity
/// binds) writes it in the block's journaled directory step ([`Directory::apply_asset_record_journaled`]). The paid
/// sign-up door refuses the kind at decode, the signed apply ([`Directory::apply_entry`]) refuses it, and a joiner takes
/// it only inside a refill sequence that folds, whole, to the certified word (audit F16), so a peer cannot slip one in.
///
/// FIELD MEANING FOR THIS KIND:
/// * `key`     — the asset's id, 64 lower-case hex characters (the chain's own derivation, `AssetCreateTx::derived_id`).
/// * `address` — the creator's id, 64 hex characters.
/// * `name`    — `kind ␟ symbol ␟ name ␟ logo digest hex` (kind is `token` or `nft`; `␟` is U+001F).
/// * `topic`   — empty (the collection is filed by the asset's mint: [`KIND_ASSET_FILE`]).
/// * `pic`     — the picture's digest when the creation put the picture's bytes on the chain, else `None`. (It equals
///               the logo digest in `name`; `None` says "the chain was given no bytes for it".)
/// * `pubkey` / `sig` — empty.
///
/// A CREATION IS NOT SIGNED BY THE CREATOR IT NAMES, so more than one creation of one asset can fold. The first writes
/// the record. A later one changes it in ONE way only: it adds the picture to a record that has none, which is safe
/// from anyone because a picture can only be the true one (it must hash to the logo digest the asset's identity
/// binds). So nobody can keep an asset's picture off the chain by creating the asset first without it.
pub const KIND_ASSET: u8 = 5;

/// ⭐ AN ASSET FILED UNDER A COLLECTION (spec §12.6) — written by the fold of the asset's MINT and by nothing else. The
/// mint is the one object of an asset that only its creator can make (the creator's ML-DSA signature covers the
/// handle) and that happens once (it retires the asset's issue right), so "which collection" is said once, by the
/// creator. No signature rides here: the mint's own door verified it; like [`KIND_ASSET`], this kind is refused at
/// the paid door's decode and by the signed apply, and a joiner takes it only inside a certified refill sequence.
///
/// FIELD MEANING FOR THIS KIND:
/// * `key`     — the asset's id, 64 lower-case hex characters.
/// * `topic`   — the collection's canonical handle. Kept only when that collection exists NOW and its owner is the
///               asset's creator, so nobody files a piece under someone else's collection; otherwise nothing is
///               written and no entry is logged.
/// * every other field — empty.
pub const KIND_ASSET_FILE: u8 = 6;

/// ⭐ AN ASSET'S WHOLE SUPPLY (spec §14.3, user 2026-11-12: "the tokenomics should appear on each liquidity pool showing
/// total supply") — written by the fold of the object that mints the asset (a creation that carries its supply, or the
/// asset's one mint) and by nothing else. An asset is minted once (its issue right is retired by that object), so this
/// is said once, and the amount is already public in the minting object. Like [`KIND_ASSET_FILE`], this kind is refused
/// at the paid door's decode and by the signed apply, and a joiner takes it only inside a certified refill sequence.
///
/// FIELD MEANING FOR THIS KIND:
/// * `key`  — the asset's id, 64 lower-case hex characters.
/// * `name` — the supply in atomic units, as decimal digits (no sign, no leading zero).
/// * every other field — empty.
pub const KIND_ASSET_SUPPLY: u8 = 7;

/// A collection handle's longest form, and the bounds of what a collection says about itself. PROTOCOL SHAPE constants:
/// one collection entry is at most about 31 KB with its key and signature, inside `dir_entry_tx::DIR_ENTRY_BYTES_MAX`.
pub const COLLECTION_HANDLE_MAX: usize = 32;
pub const COLLECTION_TITLE_MAX: usize = 64;
pub const COLLECTION_TEXT_MAX: usize = 1024;
pub const COLLECTION_COVER_MAX: usize = 24 * 1024;
/// The largest picture a creation may put on the chain: a token's logo and an NFT's picture. Each kilobyte is paid for
/// at the directory's own price (`AssetCreateTx::creation_price`).
pub const TOKEN_ART_MAX: usize = 8 * 1024;
pub const NFT_ART_MAX: usize = 24 * 1024;

/// The picture formats the chain keeps, told by the file's own first bytes (never by a name or a claimed type): PNG,
/// JPEG, WebP. Nothing that can carry a script (an SVG) is a picture here.
#[must_use]
pub fn art_mime(art: &[u8]) -> Option<&'static str> {
    if art.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("image/png")
    } else if art.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if art.len() > 12 && &art[..4] == b"RIFF" && &art[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// Is `art` a picture the chain keeps, of at most `max` bytes? An EMPTY picture is "none" and is allowed.
#[must_use]
pub fn art_ok(art: &[u8], max: usize) -> bool {
    art.is_empty() || (art.len() <= max && art_mime(art).is_some())
}

/// Is `handle` a collection handle in its canonical form: 1 to [`COLLECTION_HANDLE_MAX`] characters of `a-z`, `0-9`,
/// `-` and `_`? (An EMPTY handle means "no collection" and is judged by the caller.)
#[must_use]
pub fn collection_handle_ok(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= COLLECTION_HANDLE_MAX
        && handle.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Hard per-entry cap on the PROFILE topic column (bio ‖ fee ‖ avatar-b64) — a PROTOCOL SHAPE constant
/// (like the 8MB body cap), so one sign-up can never bloat a block or the registry. ~24KB of base64 fits
/// a 128×128 JPEG avatar with room to spare; entries past this are refused fail-closed at verify+apply.
pub const PROFILE_TOPIC_MAX: usize = 32_000;

/// Genesis seed of the DIRECTORY ACCUMULATOR — the running blake3 fold over every APPLIED entry's wire
/// bytes, in canonical apply order. Rides the DSYNC sync state (bound, unforgeable) exactly like the
/// letter accumulator, so a jumped joiner KNOWS the certified registry endpoint and refills to it through
/// the verified door — never a silent divergence, never a scan.
pub fn dir_acc_genesis() -> [u8; 32] {
    *blake3::hash(b"MONEROUSD-DIR-ACC-GENESIS/v1").as_bytes()
}

/// ONE fold step: `acc' = blake3(acc ‖ entry_wire)`. The SAME step on produce, ingest, cascade and
/// refill, in canonical order — so every node's `dir_acc` converges by construction.
pub fn fold_dir_acc(acc: &[u8; 32], entry_wire: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(acc);
    h.update(entry_wire);
    *h.finalize().as_bytes()
}

/// ⛔ AUDIT F16 (2026-11-10) — THE CERTIFIED FORM OF THE DIRECTORY: ITS ACCUMULATOR AND ITS ENTRY COUNT IN ONE WORD.
///
/// WHAT WAS WRONG. A sync bundle certified the directory by its running accumulator alone. A joiner refilling toward it
/// could not know where the certified sequence ended, so the refill door applied and KEPT each validly signed entry a
/// peer served and only afterwards compared accumulators. A signature shows who wrote an entry, never that the chain
/// applied it: a peer signing its own sign-up for someone else's @name owned that name on the joining node.
/// THE SHAPE, BORROWED: verify the whole against the commitment before keeping any part (Bitcoin's headers-first sync
/// checks a chain of headers before it takes a block; a Merkle download is checked against its root before it is used).
/// For that the joiner must know how many entries the commitment covers, so the count rides IN the certified word:
/// 24 bytes of `blake3(domain ‖ acc ‖ count)` followed by the count's 8 little-endian bytes. The word is the value every
/// existing site already carries and binds as `dir_acc` (the snapshot field, the sync binding, the chain summary), so
/// the count is bound exactly where the accumulator was, with no new field and no new binding site to forget.
/// AN EMPTY DIRECTORY certifies to the genesis seed, as before: a pre-directory bundle and an empty one are the same
/// "nothing to chase".
/// Cons, quantified: the accumulator half of the word is 192 bits where it was 256 (collision work 2^96, far past any
/// other bound on this chain); 0 bytes more on any wire.
#[must_use]
pub fn certified_dir_acc(acc: &[u8; 32], len: u64) -> [u8; 32] {
    if len == 0 {
        return dir_acc_genesis();
    }
    let mut h = blake3::Hasher::new();
    h.update(b"MONEROUSD-DIR-ACC-CERTIFIED/v1");
    h.update(acc);
    h.update(&len.to_le_bytes());
    let mut out = [0u8; 32];
    out[..24].copy_from_slice(&h.finalize().as_bytes()[..24]);
    out[24..].copy_from_slice(&len.to_le_bytes());
    out
}

/// The entry count a certified directory word covers ([`certified_dir_acc`]): 0 for the genesis seed.
#[must_use]
pub fn certified_dir_len(certified: &[u8; 32]) -> u64 {
    if *certified == dir_acc_genesis() {
        return 0;
    }
    let mut n = [0u8; 8];
    n.copy_from_slice(&certified[24..]);
    u64::from_le_bytes(n)
}

/// One authenticated directory sign-up, carried in [`crate::block::Block::dir_set`] and re-verified at apply.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirEntry {
    /// [`KIND_NAME`] or [`KIND_GROUP`].
    pub kind: u8,
    /// The canonical key — a username (canon: `@`-optional, lowercased) or a group handle (canon: lowercased).
    pub key: String,
    /// For a username: the address it resolves to. For a group: the owner's Letter address (a joiner seals a
    /// join request to it). An opt-in routing handle either way; payments/messages to it stay confidential.
    pub address: String,
    /// Group display name (empty for a username entry).
    pub name: String,
    /// Group topic / tags (empty for a username entry).
    pub topic: String,
    /// The owner's ML-DSA-65 verification key. `owner = H(pubkey)`; only this key may re-point / transfer.
    pub pubkey: Vec<u8>,
    /// ML-DSA-65 signature over [`dir_entry_msg`]. Re-verified at apply on every node (nothing trusted).
    pub sig: Vec<u8>,
    /// ⭐ THE PICTURE THIS ENTRY NAMES, BY ITS blake3 DIGEST ([`KIND_COLLECTION`]'s cover, [`KIND_ASSET`]'s picture);
    /// `None` for every other kind (the paid door refuses one on them).
    ///
    /// ⛔ THE DIGEST, NEVER THE BYTES (decided 2026-11-11, before this field first landed). An entry is what every node
    /// folds into the certified directory word and what a joining node must take WHOLE before it can resolve anything
    /// (audit F16). A picture inside it would make a joiner download every NFT's picture before it could resolve one
    /// @username, and would weld "which node keeps which picture" into consensus. So the entry names the picture and
    /// the bytes are kept apart, by digest ([`Directory::keep_pic`]): anyone holding them can serve them, anyone
    /// receiving them checks them by hashing, and which nodes hold which pictures is a storage policy the chain's
    /// rules never read. BORROWED: content addressing (git objects, IPFS blocks; Bitcoin's block header names its
    /// transactions by a root and the bytes travel beside it).
    pub pic: Option<[u8; 32]>,
}

impl DirEntry {
    /// Postcard wire bytes. Serialization of this plain owned struct does not fail in practice; on the impossible
    /// error path we emit an empty payload, which `decode_dir_set` skips (fail-closed — the entry is simply not
    /// carried, never a torn record).
    pub fn to_wire(&self) -> Vec<u8> {
        match postcard::to_allocvec(self) {
            Ok(b) => b,
            Err(_) => Vec::new(),
        }
    }
    /// Decode one entry; a corrupt/truncated frame yields `None` (fail-closed).
    pub fn from_wire(b: &[u8]) -> Option<DirEntry> {
        match crate::chain_object::decode_exact(b) {
            Some(e) => Some(e),
            None => None,
        }
    }
}

/// THE ONE message a directory sign-up's ML-DSA signature must cover — domain-separated, so a signature for one
/// field set can never be replayed for another, and the producer + every verifier build the IDENTICAL preimage.
pub fn dir_register_msg(kind: u8, key: &str, address: &str, name: &str, topic: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(24 + key.len() + address.len() + name.len() + topic.len());
    m.extend_from_slice(b"musdm.dir.register.v1");
    m.push(kind);
    m.extend_from_slice(key.as_bytes());
    m.push(0u8);
    m.extend_from_slice(address.as_bytes());
    m.push(0u8);
    m.extend_from_slice(name.as_bytes());
    m.push(0u8);
    m.extend_from_slice(topic.as_bytes());
    m
}

/// ⭐ THE MESSAGE AN ENTRY'S SIGNATURE COVERS, from the entry itself: [`dir_register_msg`] over its canonical key, and,
/// when the entry names a picture, a separator and the picture's blake3 digest. An entry with no picture signs
/// exactly what it always signed, so a @username's or a profile's signature is unchanged; a collection's cover cannot
/// be swapped under its signature. Every verifier (the paid door, the fold, the certified refill) builds the message
/// HERE, so no two of them can disagree about what was signed.
#[must_use]
pub fn dir_entry_msg(e: &DirEntry) -> Vec<u8> {
    let canon = canon_key(e.kind, &e.key);
    let mut m = dir_register_msg(e.kind, &canon, &e.address, &e.name, &e.topic);
    if let Some(pic) = &e.pic {
        m.push(0u8);
        m.extend_from_slice(b"pic");
        m.extend_from_slice(pic);
    }
    m
}

/// CANONICAL collection handle — matched case-insensitively and trim-tolerantly, like a group's.
pub fn canon_collection(s: &str) -> String {
    s.trim().to_lowercase()
}

/// CANONICAL @username — case-insensitive + `@`-optional + whitespace-tolerant. Squatting a case/`@` variant is
/// impossible because every spelling folds to the same key. MUST match the wallet's `canon_username`.
pub fn canon_name(s: &str) -> String {
    let t = s.trim();
    let t = match t.strip_prefix('@') {
        Some(x) => x,
        None => t,
    };
    t.trim().to_lowercase()
}

/// CANONICAL group handle — a name minted by the creator, matched case-insensitively / trim-tolerantly.
pub fn canon_gid(s: &str) -> String {
    let t = s.trim();
    let t = match t.strip_prefix('@') {
        Some(x) => x,
        None => t,
    };
    t.trim().to_lowercase()
}

/// Canonical form of an entry's key for signing/verifying, BY KIND: @names and group handles fold case,
/// but a PROFILE key IS an address — exact bytes, never canonicalized (case is identity in an address).
pub fn canon_key(kind: u8, key: &str) -> String {
    match kind {
        KIND_GROUP => canon_gid(key),
        // ⭐ A HANDOVER NAMES THE SAME KEY THE REGISTRATION DID, canonicalised identically — otherwise the
        // transfer would address a different slot from the name it is selling.
        KIND_NAME_TRANSFER => canon_name(key),
        KIND_PROFILE => key.to_string(),
        KIND_COLLECTION => canon_collection(key),
        // an asset's key is its id in hex: one spelling, lower case
        KIND_ASSET | KIND_ASSET_FILE | KIND_ASSET_SUPPLY => key.trim().to_lowercase(),
        _ => canon_name(key),
    }
}

/// The new owner's id carried by a [`KIND_NAME_TRANSFER`] entry: exactly 64 hex characters decoding to the
/// 32-byte `pubkey_id` of the key that will own the name. Anything else is refused — a handover whose
/// destination cannot be read would strand the name under an owner nobody can sign for.
#[must_use]
pub fn parse_owner_id(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// PROFILE ownership is CRYPTOGRAPHIC, not first-come: a published address embeds `b = blake3(spend_pk)`,
/// so a profile entry only binds if the SIGNER'S own pubkey hashes to the address it claims. Nobody can
/// squat a profile onto someone else's address, not even once. Non-profile kinds pass through unchanged
/// (@names are first-come by design — they carry no key material to bind to).
pub fn profile_binding_ok(e: &DirEntry) -> bool {
    if e.kind != KIND_PROFILE {
        return true;
    }
    match crate::address::parse_address(&e.address) {
        Some((_, b, _)) => b == *blake3::hash(&e.pubkey).as_bytes(),
        None => false,
    }
}

/// The 32-byte index key for a directory entry: `blake3(domain ‖ kind ‖ canon_key)`. Domain-separated by kind so a
/// username and a group handle of the same spelling never collide. This is what the projection indexes on.
pub fn dir_key(kind: u8, key: &str) -> [u8; 32] {
    let canon = canon_key(kind, key);
    let mut h = blake3::Hasher::new();
    h.update(b"MONEROUSD-DIR-KEY");
    h.update(&[kind]);
    h.update(canon.as_bytes());
    *h.finalize().as_bytes()
}

/// A resolved username record.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NameRec {
    pub address: String,
    pub owner: [u8; 32],
}

/// A resolved group handle record.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GroupRec {
    pub handle: String,
    pub name: String,
    pub topic: String,
    pub owner_addr: String,
    pub owner: [u8; 32],
}

/// The directory projection — a deterministic fold of the chain's applied `dir_set`s, keyed by [`dir_key`]. NO disk.
/// `Serialize`/`Deserialize` so a DSYNC bundle can carry the whole projection to a jumped joiner (bound by a root),
/// exactly as the bond quorum rides DSYNC — a joiner that leapt over the sign-up blocks still gets the directory.
/// Every read is a `HashMap::get` (one indexed lookup); nothing here scans.
/// One published PROFILE: display name, bio, and the DM-acceptance fee in micro-USDm (0 = free).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProfileRec {
    pub display: String,
    pub bio: String,
    pub fee_micro: u64,
    pub owner: [u8; 32],
    /// Base64 of a small owner-chosen avatar image (empty ⇒ the client renders the address identicon).
    /// Chain-hosted on the signed entry itself: no photo host, no CDN, no fetch-time IP leak — viewers
    /// read it from their own node like every other profile field, and the signature binds it.
    pub avatar: String,
}

/// One collection, as the directory resolves it ([`KIND_COLLECTION`]).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollectionRec {
    pub handle: String,
    pub title: String,
    pub text: String,
    pub owner: [u8; 32],
    /// The digest of the collection's current cover, or `None`.
    pub pic: Option<[u8; 32]>,
    /// The ids of the assets recorded into this collection, in the chain's own apply order. Grows by 32 bytes per
    /// created piece (paid for by that creation), never per block or note.
    pub pieces: Vec<[u8; 32]>,
}

/// One asset's record, as the directory resolves it ([`KIND_ASSET`]).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AssetRec {
    /// The asset's id (the map is keyed by a hash of it, so the record says it).
    pub id: [u8; 32],
    /// `true` for an NFT, `false` for a token.
    pub nft: bool,
    pub symbol: String,
    pub name: String,
    pub creator: [u8; 32],
    /// The picture digest the asset's identity binds (zero when the creator bound none).
    pub logo: [u8; 32],
    /// The collection the chain recorded this asset into, or empty.
    pub collection: String,
    /// The picture's digest when the creation put its bytes on the chain (then it equals `logo`), else `None`.
    pub pic: Option<[u8; 32]>,
    /// The asset's whole supply in atomic units, once the object that minted it has folded ([`KIND_ASSET_SUPPLY`]);
    /// `None` before that. Public in that object already.
    #[serde(default)]
    pub supply: Option<u64>,
}

/// The tag every note of an asset carries, as bytes: the three limbs of the chain's own derivation
/// (`whir_rec_block::wrapped_asset_tag`), each as 8 little-endian bytes. Its hex is the wallet's spelling of a tag.
#[must_use]
pub fn asset_tag_bytes(asset_id: &[u8; 32]) -> [u8; 24] {
    let limbs = usdm_decider::whir_rec_block::wrapped_asset_tag(asset_id);
    let mut out = [0u8; 24];
    for (i, l) in limbs.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&l.to_le_bytes());
    }
    out
}

/// What an asset record's `name` field unpacks to: kind, symbol, name and the logo digest.
fn asset_facts_of(e: &DirEntry) -> Option<(bool, String, String, [u8; 32])> {
    let mut it = e.name.split('\u{1f}');
    let (kind, symbol, name, logo) = (it.next()?, it.next()?, it.next()?, it.next()?);
    if it.next().is_some() {
        return None;
    }
    let nft = match kind {
        "nft" => true,
        "token" => false,
        _ => return None,
    };
    Some((nft, symbol.to_string(), name.to_string(), parse_owner_id(logo)?))
}

/// The `name` field of an asset's record: `kind ␟ symbol ␟ name ␟ logo digest hex` (the inverse of the read above; a
/// symbol and a name hold no U+001F, which the creation's own decode refuses).
#[must_use]
pub fn asset_facts_field(nft: bool, symbol: &str, name: &str, logo: &[u8; 32]) -> String {
    let hex: String = logo.iter().map(|b| format!("{b:02x}")).collect();
    [if nft { "nft" } else { "token" }, symbol, name, hex.as_str()].join("\u{1f}")
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Directory {
    names: HashMap<[u8; 32], NameRec>,
    groups: HashMap<[u8; 32], GroupRec>,
    profiles: HashMap<[u8; 32], ProfileRec>,
    /// Collections by [`dir_key`] of their handle, and assets by [`dir_key`] of their id (spec §12.6). Registration
    /// keyed, like the three maps above: one record per paid collection entry and per paid creation.
    #[serde(default)]
    collections: HashMap<[u8; 32], CollectionRec>,
    #[serde(default)]
    assets: HashMap<[u8; 32], AssetRec>,
    /// An asset's record key by the TAG its notes carry ([`asset_tag_bytes`]): a wallet holds notes by tag and cannot
    /// turn a tag back into an id, so this is how it names what it holds, by one keyed read on its own node.
    /// 56 bytes per recorded asset, written and un-done with the record.
    #[serde(default)]
    asset_tags: HashMap<[u8; 24], [u8; 32]>,
    /// Every collection's key in the order the chain first applied it: what the marketplace's "newest first" page is
    /// read from by cursor (never a scan of the map). 32 bytes per collection.
    #[serde(default)]
    collection_order: Vec<[u8; 32]>,
    /// ⭐ THE PICTURES, BY DIGEST: the bytes of every picture a record names that this node holds. NOT part of the
    /// certified directory word (that covers the records, which name pictures by digest), so it is a store of
    /// self-checking bytes, never consensus state: a picture is kept only when a record names its digest
    /// ([`Self::keep_pic`]) and is checked by hashing; what no record names is let go when its naming is un-done or a
    /// refill replays the records ([`Self::pic_unname`]).
    /// CACHE-ONLY: a node missing one asks any peer for it by digest and checks the answer by hashing
    /// ([`Self::pics_owed`]); the records, which the chain decides, never change with what is held here.
    /// O1-FOOTPRINT-REVIEWED: each picture is bounded by protocol constant and was paid for by the kilobyte by the
    /// entry or creation that named it; which nodes hold which pictures is a holding policy (today: all of them).
    #[serde(default)]
    pics: HashMap<[u8; 32], Vec<u8>>,
    /// How many records name each picture (two assets may share one). A picture named by none is not kept.
    #[serde(default)]
    pic_refs: HashMap<[u8; 32], u32>,
    /// The pictures records name that this node does not hold yet: what it asks the mesh for, by digest.
    #[serde(default)]
    pics_owed: std::collections::BTreeSet<[u8; 32]>,
    /// The running fold over every APPLIED entry (apply order). Persisted WITH the registry so a restart
    /// resumes the exact certified endpoint it had folded to. Compared against the DSYNC-adopted target.
    #[serde(default = "dir_acc_genesis")]
    pub acc: [u8; 32],
    /// EVERY applied entry in apply order — what the refill door serves to a jumped peer, and what a
    /// reset-refill replays. Registration-keyed custody (grows per user sign-up, never per block/note),
    /// the same class as the maps above; persisted in the same registry file.
    #[serde(default)]
    log: Vec<DirEntry>,
    /// Where this registry disk-persists (None on test nodes). Registration-keyed custody, the identical
    /// class to names-{port}.json: it grows only when a user signs up (never with blocks/notes), and blocks
    /// older than the ladder span never replay on an O(1) node — without this file every @name / group /
    /// profile registered before the last restart would vanish from resolve.
    #[serde(skip)]
    persist_path: Option<std::path::PathBuf>,
}

impl Default for Directory {
    fn default() -> Self {
        Directory {
            names: HashMap::new(),
            groups: HashMap::new(),
            profiles: HashMap::new(),
            collections: HashMap::new(),
            assets: HashMap::new(),
            asset_tags: HashMap::new(),
            collection_order: Vec::new(),
            pics: HashMap::new(),
            pic_refs: HashMap::new(),
            pics_owed: std::collections::BTreeSet::new(),
            acc: dir_acc_genesis(),
            log: Vec::new(),
            persist_path: None,
        }
    }
}

/// ⭐ DB-274 (dir_set) — the slot ONE applied entry overwrote, so a fold step's effect on the directory can be taken
/// back exactly (a refused fold, or a rewind to a common block). `None` = the slot was empty before.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DirPrev {
    Name(Option<NameRec>),
    Group(Option<GroupRec>),
    Profile(Option<ProfileRec>),
    /// A collection's slot (spec §12.6). `None` = the entry CREATED the collection (its key was also pushed onto the
    /// apply order, which the undo pops).
    Collection(Option<CollectionRec>),
    /// An asset's slot before a creation's fold wrote or completed its record, or its mint's fold filed it under a
    /// collection. `None` = there was no record; `Some` = the record as it stood (the undo restores it whole, and takes
    /// back the picture naming or the collection piece the step added).
    Asset(Option<AssetRec>),
}

/// One applied entry's before-image: the slot it wrote and what was there.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirUndo {
    pub key: [u8; 32],
    pub prev: DirPrev,
}

/// ⭐ DB-274 (dir_set) — everything ONE fold step changed in the directory: each applied entry's before-image (apply
/// order), and the accumulator and log length before the step. `undo_step` restores all three; a step whose list is
/// empty applied nothing and is never journaled.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirStep {
    pub undo: Vec<DirUndo>,
    pub acc_before: [u8; 32],
    pub log_len_before: usize,
}

/// One journaled fold step of the directory, keyed by the fold ordinal it applied at (the node's `dir_fold_journal`,
/// inside the rewind reach; carried in the checkpoint's fold record so a restart can still un-fold it).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirFoldStep {
    pub ordinal: u64,
    pub step: DirStep,
}

/// ⭐ A-F38 — ONE DIRECTORY WRITE A FOLD MADE WHILE THIS NODE'S DIRECTORY WAS BEING REFILLED (the node's
/// `dir_refill_held`): what the fold would have applied, kept in fold order with the picture bytes its object carried,
/// and applied through the same gate once the certified sequence is in place ([`Directory::apply_held`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeldDirWrite {
    /// a paid, signed entry (`Class::DirEntry`). A picture it names is fetched by its digest once the entry is in
    /// place (the picture door), like every picture a refilled record names.
    Entry(DirEntry),
    /// an asset's record, written by its creation's fold, with the creation's picture bytes (empty when none)
    AssetRecord(DirEntry, Vec<u8>),
    /// an asset's filing under a collection, written by the fold of the object the creator signed
    AssetFiling(DirEntry),
    /// an asset's whole supply, written by the fold of the object that minted it ([`KIND_ASSET_SUPPLY`])
    AssetSupply(DirEntry),
}

impl Directory {
    pub fn new() -> Self {
        Self::default()
    }

    /// A-F38 — apply one held write exactly as its fold would have, against the directory as it stands NOW (the
    /// certified sequence plus every held write before this one), journaled into `step`. `true` when the directory
    /// changed. The caller decides what the step is: a throwaway one for a write whose fold step has closed (like a
    /// refilled entry it then belongs to no step this node can un-fold; the caller raises its journal floor, and a
    /// rewind below it marks the directory stale), or the fold's own open step, so a refusal of that step un-does it.
    pub fn apply_held(&mut self, w: &HeldDirWrite, step: &mut DirStep) -> bool {
        match w {
            HeldDirWrite::Entry(e) => self.apply_entry_journaled(e, crate::pqauth::pubkey_id(&e.pubkey), step),
            HeldDirWrite::AssetRecord(e, art) => {
                let applied = self.apply_asset_record_journaled(e, step);
                if applied && !art.is_empty() {
                    let _ = self.keep_pic(art);
                }
                applied
            }
            HeldDirWrite::AssetFiling(e) => self.apply_asset_filing_journaled(e, step),
            HeldDirWrite::AssetSupply(e) => self.apply_asset_supply_journaled(e, step),
        }
    }

    /// Record one APPLIED entry: advance the accumulator and append to the apply-order log. Called by the
    /// node in the same act as a successful `apply_entry` — projection, log and acc move together.
    pub fn fold_applied(&mut self, e: &DirEntry) {
        self.acc = fold_dir_acc(&self.acc, &e.to_wire());
        self.log.push(e.clone());
    }

    /// The before-image of the slot entry `e` writes (by its kind and canonical key).
    fn slot_before(&self, e: &DirEntry) -> DirUndo {
        match e.kind {
            KIND_NAME | KIND_NAME_TRANSFER => {
                let k = dir_key(KIND_NAME, &e.key);
                DirUndo { key: k, prev: DirPrev::Name(self.names.get(&k).cloned()) }
            }
            KIND_GROUP => {
                let k = dir_key(KIND_GROUP, &e.key);
                DirUndo { key: k, prev: DirPrev::Group(self.groups.get(&k).cloned()) }
            }
            KIND_COLLECTION => {
                let k = dir_key(KIND_COLLECTION, &e.key);
                DirUndo { key: k, prev: DirPrev::Collection(self.collections.get(&k).cloned()) }
            }
            KIND_ASSET | KIND_ASSET_FILE | KIND_ASSET_SUPPLY => {
                let k = dir_key(KIND_ASSET, &e.key);
                DirUndo { key: k, prev: DirPrev::Asset(self.assets.get(&k).cloned()) }
            }
            _ => {
                let k = dir_key(KIND_PROFILE, &e.key);
                DirUndo { key: k, prev: DirPrev::Profile(self.profiles.get(&k).cloned()) }
            }
        }
    }

    /// [`Self::apply_entry`] + [`Self::fold_applied`] in one act, recording the slot's before-image into `step` when the
    /// entry applied — the fold step's writer (the node's `dir_step_at_fold`).
    pub fn apply_entry_journaled(&mut self, e: &DirEntry, owner: [u8; 32], step: &mut DirStep) -> bool {
        let before = self.slot_before(e);
        if !self.apply_entry(e, owner) {
            return false;
        }
        self.fold_applied(e);
        step.undo.push(before);
        true
    }

    /// A fresh, empty step over the directory as it stands now (its `acc_before` / `log_len_before` are this state's).
    pub fn begin_step(&self) -> DirStep {
        DirStep { undo: Vec::new(), acc_before: self.acc, log_len_before: self.log.len() }
    }

    /// ⭐ DB-274 (dir_set) — take ONE fold step's effect back: every slot it wrote returns to its before-image (newest
    /// first), the log is cut to its length before the step and the accumulator returns to its value — byte-identical to
    /// never having applied the step, so a re-fold from identical inputs reaches the identical directory.
    pub fn undo_step(&mut self, step: DirStep) {
        for u in step.undo.into_iter().rev() {
            match u.prev {
                DirPrev::Name(Some(r)) => {
                    self.names.insert(u.key, r);
                }
                DirPrev::Name(None) => {
                    self.names.remove(&u.key);
                }
                DirPrev::Group(Some(r)) => {
                    self.groups.insert(u.key, r);
                }
                DirPrev::Group(None) => {
                    self.groups.remove(&u.key);
                }
                DirPrev::Profile(Some(r)) => {
                    self.profiles.insert(u.key, r);
                }
                DirPrev::Profile(None) => {
                    self.profiles.remove(&u.key);
                }
                DirPrev::Collection(Some(r)) => {
                    // an owner's change of title, words or cover: the record returns whole (its pieces were not the
                    // change's to move, and any piece recorded after it was un-done before this, newest first), and
                    // the picture it names is named again (owed to this node if it let the bytes go meanwhile)
                    let now = self.collections.get(&u.key).and_then(|c| c.pic);
                    self.pic_unname(now, true);
                    self.pic_name(r.pic);
                    self.collections.insert(u.key, r);
                }
                DirPrev::Collection(None) => {
                    if let Some(c) = self.collections.remove(&u.key) {
                        self.pic_unname(c.pic, true);
                    }
                    if self.collection_order.last() == Some(&u.key) {
                        self.collection_order.pop();
                    }
                }
                DirPrev::Asset(prev) => {
                    // what the un-done write added on top of `prev`: a picture naming, a place among a collection's
                    // pieces (the newest piece there: un-done newest first), or the whole record
                    let Some(now) = self.assets.remove(&u.key) else { continue };
                    let (pic_before, collection_before) = match &prev {
                        Some(p) => (p.pic, p.collection.clone()),
                        None => (None, String::new()),
                    };
                    if now.pic != pic_before {
                        self.pic_unname(now.pic, true);
                    }
                    if now.collection != collection_before {
                        if let Some(c) = self.collections.get_mut(&dir_key(KIND_COLLECTION, &now.collection)) {
                            c.pieces.pop();
                        }
                    }
                    match prev {
                        Some(p) => {
                            self.assets.insert(u.key, p);
                        }
                        None => {
                            self.asset_tags.remove(&asset_tag_bytes(&now.id));
                        }
                    }
                }
            }
        }
        self.log.truncate(step.log_len_before);
        self.acc = step.acc_before;
        self.persist_now();
    }

    /// One PAGE of the apply-order log for the refill door (postcard entries, bounded count).
    pub fn log_page(&self, from: usize, max: usize) -> Vec<DirEntry> {
        if from >= self.log.len() {
            return Vec::new();
        }
        let end = (from + max).min(self.log.len());
        self.log[from..end].to_vec()
    }

    pub fn log_len(&self) -> usize {
        self.log.len()
    }

    /// RESET for a certified refill: a jumped node's log has GAPS (it missed the spans it leapt), and the
    /// fold is order-sensitive — a gapped log can never re-fold to the certified acc. So the projection,
    /// log and acc restart from genesis and the refill door re-delivers the FULL certified sequence, each
    /// entry re-verified through the same apply gate. One-time on divergence; the persist path is kept.
    /// Reset for a certified refill — and HAND BACK the applied log instead of destroying it.
    ///
    /// The returned entries are everything this registry had applied locally; the caller re-queues
    /// them for block carriage so a registration that the certified sequence does NOT yet contain is
    /// RE-CARRIED rather than lost. MEASURED (gate step-5, scratch /tmp/musd-ecocheck-S0wbsg): W2's
    /// profile applied on its own node, the carrier block lost the DAG race, the next DSYNC adopt's
    /// certified dir_acc predated the entry → this reset wiped it while `pending_dir` had already
    /// drained it as "landed" — the sign-up was in NEITHER place, /dir/register had answered
    /// queued=true, and the profile never resolved anywhere again. Works-or-fails forbids exactly
    /// that silent loss. Entries already inside the refilled certified sequence drain right back out
    /// of the pending queue at apply (the same landed-prune), and every re-carried entry re-passes
    /// the FULL apply gate (signature, address binding, owner continuity) — idempotent and sound.
    pub fn reset_for_refill(&mut self) -> Vec<DirEntry> {
        let orphaned = std::mem::take(&mut self.log);
        self.names.clear();
        self.groups.clear();
        self.profiles.clear();
        self.collections.clear();
        self.assets.clear();
        self.asset_tags.clear();
        self.collection_order.clear();
        // the records restart, so nothing names a picture until the refill replays them; the bytes already held stay
        // (they are self-checking, and the replay names most of them again), and any no record names afterwards is
        // dropped when the refill completes ([`Self::drop_unnamed_pics`])
        self.pic_refs.clear();
        self.pics_owed.clear();
        self.acc = dir_acc_genesis();
        orphaned
    }

    /// Open the disk-persisted registry at `path`: load what is there (missing/corrupt ⇒ start empty — the chain
    /// re-folds new entries forward; never a crash) and auto-save on every future applied entry.
    pub fn open(path: std::path::PathBuf) -> Self {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let mut d: Directory = std::fs::read(&path)
            .ok()
            .and_then(|b| crate::chain_object::decode_exact(&b))
            .unwrap_or_default();
        d.persist_path = Some(path);
        d
    }

    /// Atomically persist (temp + rename — a crash mid-write never tears the file). Best-effort: an IO error can
    /// NEVER halt a registration or block apply (liveness pillar); the entry stays live in memory and gossip.
    fn save(&self) {
        let Some(path) = self.persist_path.as_ref() else {
            return;
        };
        let Ok(bytes) = postcard::to_allocvec(self) else {
            return;
        };
        let tmp = path.with_extension("bin.tmp");
        // O1-FOOTPRINT-REVIEWED: feedback_asset_registry_disk_persist — registration-keyed registry custody
        // (identical class to names-{port}.json; grows per user sign-up, never per block/note).
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    /// Persist immediately (the node calls this once per block whose dir_set changed the registry).
    pub fn persist_now(&self) {
        self.save();
    }

    /// ⭐ A-F38 (the restart half) — THE MARKER A REFILL LEAVES BESIDE THE REGISTRY WHILE IT IS OWED: the certified
    /// word it is filling toward (`Some`), removed when the refill lands (`None`). The owed word itself lives in the
    /// node's memory with the stage and the fold's held writes; a restart loses all three, and the registry file it
    /// reads back is then an emptied or half-refilled directory with nothing to say so. [`Self::refill_was_owed`] is
    /// what says so at the next boot.
    /// LOCAL-STORAGE-REQUIRED: this node's own recovery state, beside its own registry file; nothing a peer serves and
    /// nothing any other node reads.
    /// bound: one file of 32 bytes per node, written at an adopt that arms a refill and removed when the refill lands.
    /// cons: none on any growth axis — exactly 32 B x 1 file per node, a function of fixed constants and never of
    /// height, blocks, notes or directory entries (0 B per block, 0 B per entry); one write per adopt that arms a
    /// refill and one unlink when it lands.
    pub fn mark_refill_owed(&self, word: Option<&[u8; 32]>) {
        let Some(path) = self.persist_path.as_ref().map(|p| p.with_extension("owed")) else {
            return;
        };
        match word {
            // O1-FOOTPRINT-REVIEWED: one fixed 32-byte file, overwritten in place; never per block, note or entry.
            Some(w) => {
                let _ = std::fs::write(&path, w);
            }
            None => {
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    /// Was a refill owed when this registry was last written? (`false` for a directory with no file.)
    pub fn refill_was_owed(&self) -> bool {
        self.persist_path.as_ref().is_some_and(|p| p.with_extension("owed").exists())
    }

    /// Total records held (names, groups, profiles, collections, assets) — the boot log's restored count.
    pub fn total(&self) -> usize {
        self.names.len() + self.groups.len() + self.profiles.len() + self.collections.len() + self.assets.len()
    }

    /// Apply ONE sign-up whose ML-DSA signature the caller has ALREADY verified, with the derived
    /// `owner = H(pubkey)`. First-come claims the key; an existing key may only be re-pointed by its CURRENT owner
    /// (a DIFFERENT owner is refused fail-closed, never overwriting). Returns `true` iff state CHANGED (so the
    /// caller's re-gossip / fold accounting fires only on a real change — an echo/no-op does not).
    pub fn apply_entry(&mut self, e: &DirEntry, owner: [u8; 32]) -> bool {
        match e.kind {
            KIND_NAME => {
                let k = dir_key(KIND_NAME, &e.key);
                match self.names.get(&k) {
                    Some(r) if r.owner != owner => false, // taken by another owner — refuse
                    Some(r) if r.address == e.address => false, // identical re-claim — no-op
                    _ => {
                        self.names.insert(
                            k,
                            NameRec {
                                address: e.address.clone(),
                                owner,
                            },
                        );
                        true
                    }
                }
            }
            // ⭐⭐⭐ THE HANDOVER. Authorised by the CURRENT owner and by nobody else; every node reaches
            // the same verdict from the entry's own bytes.
            //
            // ⛔ FAIL-CLOSED ON EVERY MISSING PRECONDITION: an unregistered name has no owner to authorise
            // anything, a signer who is not the recorded owner is a thief, and a malformed new-owner id
            // would strand the name under an owner nobody holds the key for — each is refused, and the
            // name stays exactly where it was.
            KIND_NAME_TRANSFER => {
                let k = dir_key(KIND_NAME, &e.key);
                let Some(rec) = self.names.get(&k) else {
                    return false; // nothing registered under this name — there is nothing to hand over
                };
                if rec.owner != owner {
                    return false; // ⛔ THEFT: the signer is not the current owner
                }
                let Some(new_owner) = parse_owner_id(&e.name) else {
                    return false; // a handover to an unreadable id would strand the name forever
                };
                if new_owner == owner {
                    return false; // a handover to yourself moves nothing — refuse rather than log a no-op
                }
                self.names.insert(
                    k,
                    NameRec {
                        address: e.address.clone(),
                        owner: new_owner,
                    },
                );
                true
            }
            KIND_GROUP => {
                let k = dir_key(KIND_GROUP, &e.key);
                match self.groups.get(&k) {
                    Some(r) if r.owner != owner => false,
                    Some(r)
                        if r.name == e.name && r.topic == e.topic && r.owner_addr == e.address =>
                    {
                        false
                    }
                    _ => {
                        self.groups.insert(
                            k,
                            GroupRec {
                                handle: canon_gid(&e.key),
                                name: e.name.clone(),
                                topic: e.topic.clone(),
                                owner_addr: e.address.clone(),
                                owner,
                            },
                        );
                        true
                    }
                }
            }
            KIND_PROFILE => {
                // Keyed by the OWNER'S OWN ADDRESS: the entry's `key` must equal its `address`, so a
                // profile can only ever be written by the wallet it describes (the ML-DSA verify upstream
                // already bound `owner` to the signer; here we bind the slot to that same identity).
                if e.key != e.address {
                    return false;
                }
                if e.topic.len() > PROFILE_TOPIC_MAX {
                    return false; // one sign-up can never bloat a block/registry — refused fail-closed
                }
                let k = dir_key(KIND_PROFILE, &e.key);
                // topic carries "bio\u{1f}fee_micro\u{1f}avatar_b64" (unit-separator packed — no JSON
                // dependency; the third field is optional and empty for identicon-only profiles).
                let (bio, fee_micro, avatar) = match e.topic.split_once('\u{1f}') {
                    Some((b, rest)) => match rest.split_once('\u{1f}') {
                        Some((f, av)) => (b.to_string(), f.parse::<u64>().unwrap_or(0), av.to_string()),
                        None => (b.to_string(), rest.parse::<u64>().unwrap_or(0), String::new()),
                    },
                    None => (e.topic.clone(), 0, String::new()),
                };
                match self.profiles.get(&k) {
                    Some(r) if r.owner != owner => false,
                    Some(r)
                        if r.display == e.name
                            && r.bio == bio
                            && r.fee_micro == fee_micro
                            && r.avatar == avatar =>
                    {
                        false
                    }
                    _ => {
                        self.profiles.insert(
                            k,
                            ProfileRec {
                                display: e.name.clone(),
                                bio,
                                fee_micro,
                                avatar,
                                owner,
                            },
                        );
                        true
                    }
                }
            }
            // ⭐ A COLLECTION (spec §12.6): first come by handle, and after that only its owner changes what it says.
            // Every bound is checked HERE as well as at the paid door's decode, so the certified refill, which replays
            // entries without their paid objects, applies exactly what the fold applied.
            KIND_COLLECTION => {
                let handle = canon_collection(&e.key);
                if !collection_handle_ok(&handle)
                    || e.name.is_empty()
                    || e.name.len() > COLLECTION_TITLE_MAX
                    || e.topic.len() > COLLECTION_TEXT_MAX
                    || !e.address.is_empty()
                {
                    return false;
                }
                let k = dir_key(KIND_COLLECTION, &handle);
                let old = match self.collections.get_mut(&k) {
                    Some(r) if r.owner != owner => return false, // another owner's handle
                    Some(r) => {
                        if r.title == e.name && r.text == e.topic && r.pic == e.pic {
                            return false; // says what it already says
                        }
                        r.title = e.name.clone();
                        r.text = e.topic.clone();
                        std::mem::replace(&mut r.pic, e.pic)
                    }
                    None => {
                        self.collections.insert(
                            k,
                            CollectionRec { handle, title: e.name.clone(), text: e.topic.clone(), owner, pic: e.pic, pieces: Vec::new() },
                        );
                        self.collection_order.push(k);
                        None
                    }
                };
                // the cover it names now is named, the one it named before is not; the old cover's bytes stay (see
                // `pic_unname`: a rewind of this entry must find them still here)
                self.pic_name(e.pic);
                self.pic_unname(old, false);
                true
            }
            // ⛔ AN ASSET'S RECORD AND ITS FILING ARE NEVER SIGN-UPS: only a creation's and a mint's own folds write them
            // ([`Self::apply_asset_record`], [`Self::apply_asset_filing`]). A signed entry of either kind, whoever
            // signed it, changes nothing.
            _ => false, // unknown kind — ignore (forward-compatible, never a panic)
        }
    }

    /// ⭐ WRITE ONE ASSET'S RECORD, OR ADD ITS PICTURE (spec §12.6). Called by the fold of a creation of the asset, and by
    /// the certified refill replaying the sequence the chain applied; never for a sign-up. The first creation writes
    /// the record. A later creation of the SAME asset (same creator, kind, symbol, name and logo digest: the id binds
    /// all of them) changes it only by naming the picture where the record names none. Returns the entry as logged, or
    /// `None` when nothing changed.
    #[must_use]
    pub fn apply_asset_record(&mut self, e: &DirEntry) -> Option<DirEntry> {
        if e.kind != KIND_ASSET || !e.pubkey.is_empty() || !e.sig.is_empty() || !e.topic.is_empty() {
            return None;
        }
        let id = parse_owner_id(&e.key)?; // exactly 64 hex characters
        if e.key != canon_key(KIND_ASSET, &e.key) {
            return None; // one spelling of an id
        }
        let creator = parse_owner_id(&e.address)?;
        let (nft, symbol, name, logo) = asset_facts_of(e)?;
        if e.pic.is_some_and(|p| p != logo) {
            return None; // a picture that is not the one this asset's identity binds
        }
        let k = dir_key(KIND_ASSET, &e.key);
        match self.assets.get_mut(&k) {
            Some(rec) => {
                // the same asset, created again: only a picture where there was none
                let same = rec.creator == creator && rec.nft == nft && rec.symbol == symbol && rec.name == name && rec.logo == logo;
                if !same || rec.pic.is_some() || e.pic.is_none() {
                    return None;
                }
                rec.pic = e.pic;
            }
            None => {
                self.asset_tags.insert(asset_tag_bytes(&id), k);
                self.assets.insert(k, AssetRec { id, nft, symbol, name, creator, logo, collection: String::new(), pic: e.pic, supply: None });
            }
        }
        self.pic_name(e.pic);
        Some(e.clone())
    }

    /// ⭐ FILE AN ASSET UNDER A COLLECTION (spec §12.6; [`KIND_ASSET_FILE`]). Called by the fold of the asset's mint
    /// (whose creator signature covers the handle, verified at the mint's own door) and by the certified refill.
    /// Written once: an asset already filed is not filed again. THE RULE reads this directory alone, so every node
    /// folding the same order files the same: the asset has a record, the collection exists NOW, and the collection's
    /// owner is the asset's creator. Returns the entry as logged, or `None` when nothing was written.
    #[must_use]
    pub fn apply_asset_filing(&mut self, e: &DirEntry) -> Option<DirEntry> {
        if e.kind != KIND_ASSET_FILE || !e.pubkey.is_empty() || !e.sig.is_empty() || e.pic.is_some() || !e.address.is_empty() || !e.name.is_empty() {
            return None;
        }
        let id = parse_owner_id(&e.key)?;
        if e.key != canon_key(KIND_ASSET_FILE, &e.key) {
            return None;
        }
        let handle = canon_collection(&e.topic);
        if !collection_handle_ok(&handle) || handle != e.topic {
            return None;
        }
        let k = dir_key(KIND_ASSET, &e.key);
        let creator = match self.assets.get(&k) {
            Some(rec) if rec.collection.is_empty() => rec.creator,
            _ => return None, // no record, or already filed
        };
        match self.collections.get_mut(&dir_key(KIND_COLLECTION, &handle)) {
            Some(c) if c.owner == creator => c.pieces.push(id),
            _ => return None, // no such collection, or someone else's
        }
        if let Some(rec) = self.assets.get_mut(&k) {
            rec.collection = handle;
        }
        Some(e.clone())
    }

    /// [`Self::apply_asset_record`] and [`Self::fold_applied`] in one act, journaled into `step`: the creation fold's
    /// writer (the node's `record_asset_at_fold`), un-done with its block by [`Self::undo_step`].
    pub fn apply_asset_record_journaled(&mut self, e: &DirEntry, step: &mut DirStep) -> bool {
        let before = self.slot_before(e);
        let Some(recorded) = self.apply_asset_record(e) else {
            return false;
        };
        self.fold_applied(&recorded);
        step.undo.push(before);
        true
    }

    /// [`Self::apply_asset_filing`] and [`Self::fold_applied`] in one act, journaled into `step`: the mint fold's writer
    /// (the node's `file_asset_at_fold`), un-done with its block by [`Self::undo_step`].
    pub fn apply_asset_filing_journaled(&mut self, e: &DirEntry, step: &mut DirStep) -> bool {
        let before = self.slot_before(e);
        let Some(filed) = self.apply_asset_filing(e) else {
            return false;
        };
        self.fold_applied(&filed);
        step.undo.push(before);
        true
    }

    /// The entry a mint's fold files an asset under a collection with ([`KIND_ASSET_FILE`]).
    #[must_use]
    pub fn asset_filing_entry(asset_id: &[u8; 32], collection: &str) -> DirEntry {
        DirEntry {
            kind: KIND_ASSET_FILE,
            key: asset_id.iter().map(|b| format!("{b:02x}")).collect(),
            address: String::new(),
            name: String::new(),
            topic: collection.to_string(),
            pubkey: Vec::new(),
            sig: Vec::new(),
            pic: None,
        }
    }

    /// ⭐ RECORD AN ASSET'S WHOLE SUPPLY ([`KIND_ASSET_SUPPLY`]). Called by the fold of the object that minted the asset
    /// and by the certified refill. Written once: the asset must have a record and no supply yet. Returns the entry as
    /// logged, or `None` when nothing was written.
    #[must_use]
    pub fn apply_asset_supply(&mut self, e: &DirEntry) -> Option<DirEntry> {
        if e.kind != KIND_ASSET_SUPPLY || !e.pubkey.is_empty() || !e.sig.is_empty() || e.pic.is_some() || !e.address.is_empty() || !e.topic.is_empty() {
            return None;
        }
        parse_owner_id(&e.key)?;
        if e.key != canon_key(KIND_ASSET_SUPPLY, &e.key) {
            return None;
        }
        // one spelling of a number: digits only, no leading zero, and it fits 64 bits
        if e.name.is_empty() || !e.name.bytes().all(|b| b.is_ascii_digit()) || (e.name.len() > 1 && e.name.starts_with('0')) {
            return None;
        }
        let supply: u64 = e.name.parse().ok()?;
        match self.assets.get_mut(&dir_key(KIND_ASSET, &e.key)) {
            Some(rec) if rec.supply.is_none() => rec.supply = Some(supply),
            _ => return None, // no record, or the supply is already said
        }
        Some(e.clone())
    }

    /// [`Self::apply_asset_supply`] and [`Self::fold_applied`] in one act, journaled into `step`: the minting fold's writer.
    pub fn apply_asset_supply_journaled(&mut self, e: &DirEntry, step: &mut DirStep) -> bool {
        let before = self.slot_before(e);
        let Some(said) = self.apply_asset_supply(e) else {
            return false;
        };
        self.fold_applied(&said);
        step.undo.push(before);
        true
    }

    /// The entry the minting fold records an asset's whole supply with ([`KIND_ASSET_SUPPLY`]).
    #[must_use]
    pub fn asset_supply_entry(asset_id: &[u8; 32], supply: u64) -> DirEntry {
        DirEntry {
            kind: KIND_ASSET_SUPPLY,
            key: asset_id.iter().map(|b| format!("{b:02x}")).collect(),
            address: String::new(),
            name: supply.to_string(),
            topic: String::new(),
            pubkey: Vec::new(),
            sig: Vec::new(),
            pic: None,
        }
    }

    /// An asset's record by its id (64 hex characters), in ONE indexed read. None if the chain recorded none.
    pub fn resolve_asset(&self, id_hex: &str) -> Option<&AssetRec> {
        self.assets.get(&dir_key(KIND_ASSET, id_hex))
    }

    /// An asset's record by the TAG its notes carry (48 hex characters, the wallet's own spelling of a tag), in two
    /// indexed reads. None if the chain recorded no asset with that tag.
    pub fn resolve_asset_by_tag(&self, tag_hex: &str) -> Option<&AssetRec> {
        let t = tag_hex.trim();
        if t.len() != 48 {
            return None;
        }
        let mut tag = [0u8; 24];
        for (i, b) in tag.iter_mut().enumerate() {
            *b = u8::from_str_radix(t.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        self.assets.get(self.asset_tags.get(&tag)?)
    }

    /// An asset's picture, when the chain was given one and this node holds its bytes. Empty otherwise (a picture this
    /// node does not hold yet is owed: [`Self::pics_owed`]).
    pub fn asset_art(&self, id_hex: &str) -> &[u8] {
        self.resolve_asset(id_hex).and_then(|r| r.pic).map_or(&[][..], |p| self.pic_bytes(&p))
    }

    // ── the pictures, by digest ──────────────────────────────────────────────────────────────────────────────────

    /// One more record names this picture: it is owed to this node until its bytes are held.
    fn pic_name(&mut self, pic: Option<[u8; 32]>) {
        let Some(p) = pic else { return };
        *self.pic_refs.entry(p).or_insert(0) += 1;
        if !self.pics.contains_key(&p) {
            self.pics_owed.insert(p);
        }
    }

    /// One record fewer names this picture; when none does it is owed no more, and with `let_go` its bytes are dropped.
    ///
    /// ⛔ WHEN THE BYTES ARE LET GO, AND WHEN THEY ARE NOT. `let_go` is `true` only where the naming itself is being
    /// UN-DONE (a rewound fold step): the bytes arrived beside the object that named them, and they arrive again when
    /// that object is folded again. It is `false` where a LATER entry replaced the picture (an owner's new cover): the
    /// old cover's bytes came with an older object that no rewind of the newer one will carry back, so dropping them
    /// would lose a paid-for picture on every node if the newer entry were then rewound. They stay, unnamed, until a
    /// refill replays the records ([`Self::drop_unnamed_pics`]). cons: a replaced cover (at most 24 KB, paid for when
    /// it was published) stays on the nodes that folded it until then.
    fn pic_unname(&mut self, pic: Option<[u8; 32]>, let_go: bool) {
        let Some(p) = pic else { return };
        let left = match self.pic_refs.get_mut(&p) {
            Some(n) if *n > 1 => {
                *n -= 1;
                *n
            }
            _ => 0,
        };
        if left == 0 {
            self.pic_refs.remove(&p);
            self.pics_owed.remove(&p);
            if let_go {
                self.pics.remove(&p);
            }
        }
    }

    /// ⭐ KEEP A PICTURE'S BYTES, if a record names them. The digest is computed HERE from the bytes, so nothing can be
    /// kept under a name it does not hash to; bytes no record names are refused, so nothing unpaid is ever kept; a
    /// picture already held changes nothing. `true` when the bytes were newly kept. The same door for the fold (the
    /// bytes arrive beside the entry or the creation that names them) and for a picture fetched from a peer.
    pub fn keep_pic(&mut self, bytes: &[u8]) -> bool {
        if bytes.is_empty() || bytes.len() > NFT_ART_MAX.max(COLLECTION_COVER_MAX) || art_mime(bytes).is_none() {
            return false;
        }
        let digest = *blake3::hash(bytes).as_bytes();
        if !self.pic_refs.contains_key(&digest) || self.pics.contains_key(&digest) {
            return false;
        }
        self.pics.insert(digest, bytes.to_vec());
        self.pics_owed.remove(&digest);
        true
    }

    /// A picture's bytes by its digest; empty when this node does not hold it.
    pub fn pic_bytes(&self, digest: &[u8; 32]) -> &[u8] {
        self.pics.get(digest).map_or(&[][..], Vec::as_slice)
    }

    /// Up to `max` digests of pictures records name that this node does not hold: what it asks peers for.
    pub fn pics_owed(&self, max: usize) -> Vec<[u8; 32]> {
        self.pics_owed.iter().take(max).copied().collect()
    }

    /// Let go of every picture no record names. Run when a refill has replayed the records: what the replay named is
    /// kept, anything left from before it is not.
    pub fn drop_unnamed_pics(&mut self) {
        let refs = &self.pic_refs;
        self.pics.retain(|d, _| refs.contains_key(d));
    }

    /// A collection by its handle, in ONE indexed read.
    pub fn resolve_collection(&self, handle: &str) -> Option<&CollectionRec> {
        self.collections.get(&dir_key(KIND_COLLECTION, handle))
    }

    /// A collection's cover, when it names one and this node holds its bytes. Empty otherwise.
    pub fn collection_cover(&self, handle: &str) -> &[u8] {
        self.resolve_collection(handle).and_then(|r| r.pic).map_or(&[][..], |p| self.pic_bytes(&p))
    }

    /// One page of a collection's pieces (asset ids in the chain's apply order) from position `from`: an index range of
    /// this node's own copy, never a scan. Also answers how many pieces there are, so a reader knows when it has all.
    pub fn collection_pieces_page(&self, handle: &str, from: usize, max: usize) -> (Vec<[u8; 32]>, usize) {
        match self.resolve_collection(handle) {
            Some(r) => {
                let end = from.saturating_add(max).min(r.pieces.len());
                (r.pieces.get(from..end).map(<[_]>::to_vec).unwrap_or_default(), r.pieces.len())
            }
            None => (Vec::new(), 0),
        }
    }

    /// One page of every collection, NEWEST FIRST, skipping the `skip` newest: an index range of the apply order, never
    /// a scan. Also answers how many collections there are.
    pub fn collections_page(&self, skip: usize, max: usize) -> (Vec<&CollectionRec>, usize) {
        let n = self.collection_order.len();
        let page = self
            .collection_order
            .iter()
            .rev()
            .skip(skip)
            .take(max)
            .filter_map(|k| self.collections.get(k))
            .collect();
        (page, n)
    }

    /// Resolve an ADDRESS → its published profile, in ONE indexed read. None if never published.
    pub fn resolve_profile(&self, address: &str) -> Option<&ProfileRec> {
        self.profiles.get(&dir_key(KIND_PROFILE, address))
    }

    /// Resolve `@name` → its current address, in ONE indexed read. None if unregistered.
    pub fn resolve_name(&self, name: &str) -> Option<&str> {
        match self.names.get(&dir_key(KIND_NAME, name)) {
            Some(r) => Some(r.address.as_str()),
            None => None,
        }
    }

    /// The key that owns `@name` (`H(owner ML-DSA pubkey)`), in ONE indexed read: what a `name.mud` site is looked up
    /// under ([`crate::veil::resolve_mud`]). None if unregistered.
    pub fn owner_of(&self, name: &str) -> Option<[u8; 32]> {
        self.names.get(&dir_key(KIND_NAME, name)).map(|r| r.owner)
    }

    /// Every registered `@name`'s spelling, sorted, each checked against its CURRENT record: what the Sovereign
    /// browser searches for `.mud` sites on this node's own state. Read from the applied log like [`Self::names_of`];
    /// cost one pass over the applied entries per call, on the node's own wallet's ask.
    pub fn name_spellings(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .log
            .iter()
            .filter(|e| matches!(e.kind, KIND_NAME | KIND_NAME_TRANSFER))
            .map(|e| canon_name(&e.key))
            .filter(|name| self.resolve_name(name).is_some())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Every `@name` that resolves to `address` NOW, sorted: how a wallet finds its own handles after a restart or a
    /// seed restore with nothing stored. Read from the applied log (the only place the directory keeps a name's
    /// spelling; the maps are keyed by hash), each candidate checked against the name's CURRENT record, so a name
    /// re-pointed or handed over since is not returned. Cost: one string compare per applied entry, per call; a wallet
    /// asks once when it opens, of its own node.
    pub fn names_of(&self, address: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .log
            .iter()
            .filter(|e| matches!(e.kind, KIND_NAME | KIND_NAME_TRANSFER) && e.address == address)
            .map(|e| canon_name(&e.key))
            .filter(|name| self.resolve_name(name) == Some(address))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Resolve a group `@handle` → its record (a joiner reads `owner_addr` to seal a join request), in ONE
    /// indexed read. None if unregistered.
    pub fn resolve_group(&self, handle: &str) -> Option<&GroupRec> {
        self.groups.get(&dir_key(KIND_GROUP, handle))
    }

    /// ⛔ AUDIT ONLY — WHAT THIS DIRECTORY ACTUALLY RESOLVES, as three CONSTANT-SIZE digests.
    ///
    /// `Sim::cold_peer_verdict` compares [`Self::acc`] and nothing else. The accumulator is a fold over
    /// APPLIED ENTRY BYTES advanced by [`Self::fold_applied`]; the three maps below are advanced by
    /// [`Self::apply_entry`]. They are two separate calls, so a projection can move while the
    /// accumulator stands still — and it is the PROJECTION that `#64 Pay @username` reads. A node whose
    /// `names` map resolves a handle to a different address than the mesh sends that user's money to
    /// the wrong owner while its accumulator matches the chain byte for byte.
    ///
    /// SHAPE: `(digest, count)` per map — 32 bytes and a usize, never a collection. The digest is the
    /// XOR of per-record blake3 hashes, which is COMMUTATIVE, so two identical registries digest
    /// identically no matter what order their maps iterate in; the count rides alongside because a
    /// digest alone says nothing about how many records produced it. One reusable render buffer, so
    /// nothing is retained per record. Keys and records only — exactly what `resolve_*` already serves.
    ///
    /// Read by `harness::fuzz::authority_book`, which is where the comparison and its refutation live.
    /// The seven resolution maps, in this order: `names`, `groups`, `profiles`, `collections`, `assets`, `asset_tags`,
    /// `collection_order` (spec §12.6's four, declared `ChainDerived` 2026-11-12 by lane goods, which added them; the
    /// order list is digested IN ORDER, since the marketplace's "newest first" page reads it by position).
    #[cfg(test)]
    pub fn projection_digest_for_audit(&self) -> [([u8; 32], usize); 7] {
        fn fold<K: AsRef<[u8]>, V: std::fmt::Debug>(m: &HashMap<K, V>) -> ([u8; 32], usize) {
            use std::fmt::Write as _;
            let mut acc = [0u8; 32];
            let mut buf = String::new();
            for (k, r) in m.iter() {
                buf.clear();
                let _ = write!(buf, "{r:?}");
                let mut h = blake3::Hasher::new();
                h.update(b"MONEROUSD-DIR-AUDIT-CENSUS/v1");
                h.update(k.as_ref());
                h.update(buf.as_bytes());
                for (a, d) in acc.iter_mut().zip(h.finalize().as_bytes().iter()) {
                    *a ^= *d;
                }
            }
            (acc, m.len())
        }
        let ordered = {
            let mut h = blake3::Hasher::new();
            h.update(b"MONEROUSD-DIR-AUDIT-CENSUS/order/v1");
            for k in &self.collection_order {
                h.update(k);
            }
            (*h.finalize().as_bytes(), self.collection_order.len())
        };
        [
            fold(&self.names),
            fold(&self.groups),
            fold(&self.profiles),
            fold(&self.collections),
            fold(&self.assets),
            fold(&self.asset_tags),
            ordered,
        ]
    }

}

/// Encode a batch of directory entries for [`crate::block::Block::dir_set`] — `len(u32 LE) ‖ entry` repeated,
/// mirroring the bond-set framing so a reader that stops early stops CLEANLY.
pub fn encode_dir_set(entries: &[DirEntry]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for e in entries {
        let b = e.to_wire();
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(&b);
    }
    out
}

/// Decode a `dir_set` payload — the exact inverse of [`encode_dir_set`]. A truncated tail yields the entries that
/// parsed WHOLE and stops (fail-closed, never a fabricated/partial entry).
pub fn decode_dir_set(bytes: &[u8]) -> Vec<DirEntry> {
    let mut out: Vec<DirEntry> = Vec::new();
    let mut off = 0usize;
    while off + 4 <= bytes.len() {
        let mut l = [0u8; 4];
        l.copy_from_slice(&bytes[off..off + 4]);
        let n = u32::from_le_bytes(l) as usize;
        off += 4;
        if n == 0 || off + n > bytes.len() {
            break;
        }
        if let Some(e) = DirEntry::from_wire(&bytes[off..off + n]) {
            out.push(e);
        }
        off += n;
    }
    out
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    /// Audit F16: the certified word binds the accumulator AND the entry count. A different count over the same
    /// accumulator, or a different accumulator at the same count, is a different word; the count reads back exactly;
    /// and an empty directory certifies to the genesis seed (a bundle with nothing to chase, as before).
    #[test]
    fn the_certified_word_binds_the_accumulator_and_the_count() {
        use super::{certified_dir_acc, certified_dir_len, dir_acc_genesis, fold_dir_acc};
        let acc1 = fold_dir_acc(&dir_acc_genesis(), b"one entry");
        let acc2 = fold_dir_acc(&acc1, b"a second entry");
        let w = certified_dir_acc(&acc2, 2);
        assert_eq!(certified_dir_len(&w), 2, "the count reads back from the word");
        assert_ne!(w, certified_dir_acc(&acc2, 3), "the same accumulator at another count is another word");
        assert_ne!(w, certified_dir_acc(&acc1, 2), "another accumulator at the same count is another word");
        assert_ne!(w[..24], certified_dir_acc(&acc2, 3)[..24], "the count is inside the hashed half too, not only beside it");
        assert_eq!(certified_dir_acc(&dir_acc_genesis(), 0), dir_acc_genesis(), "an empty directory certifies to the genesis seed");
        assert_eq!(certified_dir_len(&dir_acc_genesis()), 0);
        assert_eq!(certified_dir_len(&certified_dir_acc(&acc1, u64::MAX)), u64::MAX, "every count round-trips");
    }

    /// PROFILE records: self-keyed (key must equal address), owner-continuous (another signer can never
    /// overwrite), bio+fee pack/unpack through the topic column, and a fee update by the SAME owner lands.
    #[test]
    fn profile_records_are_self_keyed_owner_continuous_and_carry_the_dm_fee() {
        let mut d = Directory::new();
        let owner_a = [7u8; 32];
        let owner_b = [9u8; 32];
        let addr = "cZkxwProfileAddr".to_string();
        let e = DirEntry {
            kind: KIND_PROFILE,
            key: addr.clone(),
            address: addr.clone(),
            name: "Cas ⚡".into(),
            topic: format!("building the private future{}250000", '\u{1f}'),
            pubkey: vec![],
            sig: vec![],
            pic: None,
        };
        assert!(d.apply_entry(&e, owner_a), "first publish lands");
        let p = d.resolve_profile(&addr).expect("resolves");
        assert_eq!(p.display, "Cas ⚡");
        assert_eq!(p.bio, "building the private future");
        assert_eq!(p.fee_micro, 250_000);
        // Another owner may NEVER take the slot.
        let mut hostile = e.clone();
        hostile.name = "impostor".into();
        assert!(!d.apply_entry(&hostile, owner_b), "foreign owner refused");
        assert_eq!(d.resolve_profile(&addr).unwrap().display, "Cas ⚡");
        // A profile keyed to someone ELSE's address is refused outright.
        let mut mismatched = e.clone();
        mismatched.key = "someoneElse".into();
        assert!(!d.apply_entry(&mismatched, owner_a), "key≠address refused");
        // The owner updates their own fee.
        let mut update = e.clone();
        update.topic = format!("bio v2{}0", '\u{1f}');
        assert!(d.apply_entry(&update, owner_a), "owner update lands");
        assert_eq!(d.resolve_profile(&addr).unwrap().fee_micro, 0);
    }


    use super::*;

    fn owner(n: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }
    fn name_entry(key: &str, addr: &str) -> DirEntry {
        DirEntry {
            kind: KIND_NAME,
            key: key.into(),
            address: addr.into(),
            name: String::new(),
            topic: String::new(),
            pubkey: vec![1],
            sig: vec![2],
            pic: None,
        }
    }
    fn group_entry(handle: &str, name: &str, topic: &str, owner_addr: &str) -> DirEntry {
        DirEntry {
            kind: KIND_GROUP,
            key: handle.into(),
            address: owner_addr.into(),
            name: name.into(),
            topic: topic.into(),
            pubkey: vec![1],
            sig: vec![2],
            pic: None,
        }
    }

    #[test]
    fn names_first_come_owner_continuity_and_squat_refused() {
        let mut d = Directory::new();
        assert!(d.apply_entry(&name_entry("Alice", "addrA"), owner(1)));
        assert_eq!(d.resolve_name("alice"), Some("addrA"));
        // Owner re-points their OWN name (case/@ variants fold to the same key).
        assert!(d.apply_entry(&name_entry("@ALICE", "addrA2"), owner(1)));
        assert_eq!(d.resolve_name("alice"), Some("addrA2"));
        // A DIFFERENT owner cannot steal it.
        assert!(!d.apply_entry(&name_entry("alice", "evil"), owner(2)));
        assert_eq!(
            d.resolve_name("Alice"),
            Some("addrA2"),
            "a squat must not overwrite"
        );
    }

    #[test]
    fn groups_resolve_and_owner_continuity_and_no_cross_kind_collision() {
        let mut d = Directory::new();
        assert!(d.apply_entry(
            &group_entry("rustdevs", "Rust Devs", "programming", "cZ1"),
            owner(1)
        ));
        assert_eq!(
            d.resolve_group("RustDevs").map(|r| r.owner_addr.as_str()),
            Some("cZ1")
        );
        // A different owner cannot re-point the handle.
        assert!(!d.apply_entry(&group_entry("rustdevs", "Hijack", "x", "cZevil"), owner(9)));
        assert_eq!(
            d.resolve_group("rustdevs").map(|r| r.name.as_str()),
            Some("Rust Devs")
        );
        // A username and a group handle of the SAME spelling do not collide (domain-separated key).
        assert!(d.apply_entry(&name_entry("rustdevs", "addrU"), owner(5)));
        assert_eq!(d.resolve_name("rustdevs"), Some("addrU"));
        assert_eq!(
            d.resolve_group("rustdevs").map(|r| r.owner_addr.as_str()),
            Some("cZ1"),
            "name did not clobber group"
        );
    }

    #[test]
    fn dir_set_encode_decode_roundtrips_and_tolerates_truncation() {
        let entries = vec![
            name_entry("alice", "addrA"),
            group_entry("g1", "Rust", "prog", "cZ1"),
        ];
        let bytes = encode_dir_set(&entries);
        let back = decode_dir_set(&bytes);
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].key, "alice");
        assert_eq!(back[1].name, "Rust");
        let cut = &bytes[..bytes.len() - 3];
        assert!(decode_dir_set(cut).len() <= 2);
    }

    // ── spec §12.6: collections, assets' records, and pictures kept by digest ───────────────────────────────────────

    /// A small picture the chain keeps: a PNG's first bytes and a body that makes each one different.
    fn png(tag: u8, len: usize) -> Vec<u8> {
        let mut p = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        p.resize(len.max(9), tag);
        p
    }
    fn digest(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    /// A collection's entry naming `cover` by its digest (`None` = no cover).
    fn collection_entry(handle: &str, title: &str, text: &str, cover: Option<&[u8]>) -> DirEntry {
        DirEntry {
            kind: KIND_COLLECTION,
            key: handle.into(),
            address: String::new(),
            name: title.into(),
            topic: text.into(),
            pubkey: Vec::new(),
            sig: Vec::new(),
            pic: cover.map(digest),
        }
    }

    fn hex32(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// An asset's record as a creation's fold builds it (`AssetCreateTx::dir_record`): `art` is the picture the
    /// creation carried (`None` when it carried none); `logo_of` is the picture the asset's identity binds (so a record
    /// may bind a logo and carry no bytes, as a creation with no picture on the chain does).
    fn asset_entry(id: u8, creator: [u8; 32], nft: bool, logo_of: Option<&[u8]>, art: Option<&[u8]>) -> DirEntry {
        DirEntry {
            kind: KIND_ASSET,
            key: hex32(&[id; 32]),
            address: hex32(&creator),
            name: asset_facts_field(nft, "APE", "Ape", &logo_of.map_or([0u8; 32], digest)),
            topic: String::new(),
            pubkey: Vec::new(),
            sig: Vec::new(),
            pic: art.map(digest),
        }
    }
    /// The entry an asset's mint files it under a collection with.
    fn filing(id: u8, handle: &str) -> DirEntry {
        Directory::asset_filing_entry(&[id; 32], handle)
    }

    /// A collection's handle is first come; after that only its owner changes what it says, and a change that says the
    /// same thing changes nothing. A handle, a title or words outside the bounds is refused.
    #[test]
    fn a_collection_is_first_come_and_only_its_owner_changes_it() {
        let mut d = Directory::new();
        let (alice, mallory) = (owner(1), owner(2));
        let (c1, c3) = (png(1, 400), png(3, 500));
        let first = collection_entry("apes", "Apes", "the first apes", Some(&c1));
        assert!(d.apply_entry(&first, alice), "the first claim of a handle applies");
        d.fold_applied(&first);
        assert!(d.keep_pic(&c1), "the cover the entry names is kept by its digest");
        let rec = d.resolve_collection("apes").expect("the collection resolves");
        assert_eq!((rec.title.as_str(), rec.owner), ("Apes", alice));
        assert_eq!(d.collection_cover("apes"), c1.as_slice(), "its cover is the bytes its owner published");
        // CALIBRATION: Mallory's entry is well formed (it applies on a directory that has no `apes`)
        let theft = collection_entry("apes", "Mallory's apes", "", None);
        assert!(Directory::new().apply_entry(&theft, mallory), "CALIBRATION: the thief's entry is a valid collection entry");
        assert!(!d.apply_entry(&theft, mallory), "⛔ another key took a collection's handle");
        assert_eq!(d.resolve_collection("APES ").map(|r| r.title.as_str()), Some("Apes"), "the handle matches in any case");
        assert!(!d.apply_entry(&first, alice), "an entry that says what the collection already says changes nothing");
        let renamed = collection_entry("apes", "Great Apes", "the first apes", Some(&c3));
        assert!(d.apply_entry(&renamed, alice), "its owner changes its title and cover");
        d.fold_applied(&renamed);
        assert_eq!(d.resolve_collection("apes").map(|r| r.title.as_str()), Some("Great Apes"));
        assert_eq!(d.pic_bytes(&digest(&c1)), c1.as_slice(), "the replaced cover's bytes stay: a rewind of the change must find them");
        assert_eq!(d.pics_owed(8), vec![digest(&c3)], "the new cover is owed until its bytes arrive");
        assert!(d.keep_pic(&c3));
        assert_eq!(d.collection_cover("apes"), c3.as_slice(), "the cover read is the current entry's");
        assert_eq!(d.collections_page(0, 10).1, 1, "a change is not a second collection");
        // the bounds, each on an otherwise valid entry
        let refusals: [(&str, DirEntry); 4] = [
            ("a handle with a space", collection_entry("my apes", "T", "", None)),
            ("a handle past the bound", collection_entry(&"a".repeat(COLLECTION_HANDLE_MAX + 1), "T", "", None)),
            ("no title", collection_entry("nt", "", "", None)),
            ("words past the bound", collection_entry("wp", "T", &"w".repeat(COLLECTION_TEXT_MAX + 1), None)),
        ];
        for (what, e) in refusals {
            assert!(!d.apply_entry(&e, alice), "{what} was applied");
        }
    }

    /// ⭐ PICTURES ARE KEPT BY DIGEST, AND ONLY WHEN A RECORD NAMES THEM. The store takes bytes from anyone (the fold,
    /// or a peer answering by digest) and decides by hashing: bytes no record names are refused (nothing unpaid is
    /// kept), bytes that are not a picture or are past the bound are refused, a picture already held changes nothing,
    /// and two records naming one picture keep one copy until neither names it.
    #[test]
    fn a_picture_is_kept_by_its_digest_only_while_a_record_names_it() {
        let mut d = Directory::new();
        let alice = owner(1);
        let (shared, other) = (png(5, 600), png(6, 600));
        // ⛔ nothing names it yet: refused, whoever offers it
        assert!(!d.keep_pic(&shared), "⛔ a picture no record names was kept");
        let a = d.apply_asset_record(&asset_entry(1, alice, true, Some(&shared), Some(&shared))).expect("recorded");
        d.fold_applied(&a);
        assert_eq!(d.pics_owed(8), vec![digest(&shared)], "a named picture this node does not hold is owed");
        assert!(d.asset_art(&a.key).is_empty(), "and reads as none until its bytes arrive");
        // ⛔ a peer answering with OTHER bytes gains nothing: the digest is computed from what it sent
        assert!(!d.keep_pic(&other), "⛔ bytes that hash to no named digest were kept");
        assert!(!d.keep_pic(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), "bytes that are not a picture were kept");
        assert!(d.keep_pic(&shared), "the named picture's own bytes are kept");
        assert!(!d.keep_pic(&shared), "a picture already held changes nothing");
        assert!(d.pics_owed(8).is_empty());
        assert_eq!(d.asset_art(&a.key), shared.as_slice());
        // a second asset naming the same picture: one copy, and it stays while either names it
        let mut step = d.begin_step();
        assert!(d.apply_asset_record_journaled(&asset_entry(2, alice, true, Some(&shared), Some(&shared)), &mut step));
        assert!(d.pics_owed(8).is_empty(), "a picture already held is not owed again");
        d.undo_step(step);
        assert_eq!(d.asset_art(&a.key), shared.as_slice(), "un-doing the second record left the first one's picture");
        // a picture past the largest the chain keeps is refused even when named
        let huge = png(7, NFT_ART_MAX.max(COLLECTION_COVER_MAX) + 1);
        let h = d.apply_asset_record(&asset_entry(3, alice, true, Some(&huge), Some(&huge))).expect("the record itself is small");
        d.fold_applied(&h);
        assert!(!d.keep_pic(&huge), "a picture past the bound was kept");
    }

    /// ⭐ A CREATION IS NOT SIGNED BY THE CREATOR IT NAMES, so anyone may create an asset first. What that can do to the
    /// asset's record is NOTHING a creator loses by: the record is the same facts whoever paid, and a later creation
    /// that carries the true picture adds it. What it can NOT do: write other facts under the id, name a picture that is
    /// not the one the identity binds, replace a picture already named, or be a signed sign-up.
    #[test]
    fn an_assets_record_is_written_by_a_creation_and_a_later_creation_only_adds_its_true_picture() {
        let mut d = Directory::new();
        let alice = owner(1);
        let p7 = png(7, 200);
        // ⛔ a SIGNED entry of the asset kind, whoever signs it, changes nothing: only a creation's fold writes a record
        let bare = asset_entry(7, alice, true, Some(&p7), None);
        assert!(!d.apply_entry(&bare, alice), "⛔ a sign-up wrote an asset's record");
        assert!(d.resolve_asset(&bare.key).is_none());
        // THE FRONT-RUN: someone creates Alice's asset first, with no picture on the chain
        let first = d.apply_asset_record(&bare).expect("the record is written");
        d.fold_applied(&first);
        let rec = d.resolve_asset(&bare.key).expect("the asset resolves by its id");
        assert_eq!((rec.symbol.as_str(), rec.nft, rec.creator, rec.pic), ("APE", true, alice, None));
        let tag_hex: String = asset_tag_bytes(&[7u8; 32]).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(d.resolve_asset_by_tag(&tag_hex).map(|r| r.id), Some([7u8; 32]), "a wallet names what it holds by the tag its notes carry");
        assert!(d.resolve_asset_by_tag(&"0".repeat(48)).is_none());
        // the same creation again changes nothing
        assert!(d.apply_asset_record(&bare).is_none(), "a repeated creation wrote again");
        // ⛔ Alice's own creation, carrying the picture, is NOT locked out: the record gains the true picture
        let with = asset_entry(7, alice, true, Some(&p7), Some(&p7));
        let added = d.apply_asset_record(&with).expect("⛔ a creation that came first without the picture kept it off the chain");
        d.fold_applied(&added);
        assert!(d.keep_pic(&p7));
        assert_eq!(d.asset_art(&bare.key), p7.as_slice(), "its picture is the creation's own bytes");
        // a picture already named is never replaced, and a record's facts are never rewritten
        assert!(d.apply_asset_record(&with).is_none(), "a picture already named was written again");
        let mut other_name = asset_entry(7, alice, true, Some(&p7), Some(&p7));
        other_name.name = asset_facts_field(true, "APE", "Another Name", &digest(&p7));
        assert!(d.apply_asset_record(&other_name).is_none(), "⛔ other facts were written under an existing id");
        // ⛔ a record naming a picture that is not the one its facts bind is not a creation's record
        let mut not_its_own = asset_entry(10, alice, true, Some(&png(10, 100)), Some(&png(10, 100)));
        not_its_own.pic = Some(digest(&png(11, 100)));
        assert!(d.apply_asset_record(&not_its_own).is_none(), "⛔ a record named a picture that is not the asset's own");
        let mut signed = asset_entry(14, alice, true, None, None);
        signed.sig = vec![1];
        assert!(d.apply_asset_record(&signed).is_none(), "a record carrying a signature is not a creation's record");
        let mut with_collection = asset_entry(15, alice, true, None, None);
        with_collection.topic = "apes".into();
        assert!(d.apply_asset_record(&with_collection).is_none(), "⛔ a creation's record filed itself under a collection: only the mint files");
    }

    /// ⭐ AN ASSET IS FILED UNDER A COLLECTION BY ITS MINT, ONCE, AND ONLY UNDER ITS CREATOR'S OWN COLLECTION. (That the
    /// filing came from the creator is the mint door's signature check; this is the directory's own rule on top.)
    #[test]
    fn an_asset_is_filed_once_and_only_under_its_creators_collection() {
        let mut d = Directory::new();
        let (alice, mallory) = (owner(1), owner(2));
        for (handle, who) in [("apes", alice), ("bears", alice), ("mallorys", mallory)] {
            let c = collection_entry(handle, handle, "", None);
            assert!(d.apply_entry(&c, who));
            d.fold_applied(&c);
        }
        let piece = d.apply_asset_record(&asset_entry(7, alice, true, None, None)).expect("recorded");
        d.fold_applied(&piece);
        // ⛔ not a sign-up, whoever signs it
        assert!(!d.apply_entry(&filing(7, "apes"), alice), "⛔ a sign-up filed an asset under a collection");
        // ⛔ refused: someone else's collection, a collection that does not exist, an asset with no record
        assert!(d.apply_asset_filing(&filing(7, "mallorys")).is_none(), "⛔ a piece was filed under a collection its creator does not own");
        assert!(d.apply_asset_filing(&filing(7, "nowhere")).is_none(), "a piece was filed under a collection that does not exist");
        assert!(d.apply_asset_filing(&filing(9, "apes")).is_none(), "an asset with no record was filed");
        assert_eq!(d.resolve_asset(&piece.key).map(|r| r.collection.clone()), Some(String::new()), "CALIBRATION: nothing is filed yet");
        // the creator's own collection
        let filed = d.apply_asset_filing(&filing(7, "apes")).expect("the creator's piece is filed under the creator's collection");
        d.fold_applied(&filed);
        assert_eq!(d.resolve_asset(&piece.key).map(|r| r.collection.clone()), Some("apes".to_string()));
        assert_eq!(d.collection_pieces_page("apes", 0, 10), (vec![[7u8; 32]], 1), "and it is one of the collection's pieces");
        // once: it is not filed again, here or elsewhere
        assert!(d.apply_asset_filing(&filing(7, "apes")).is_none() && d.apply_asset_filing(&filing(7, "bears")).is_none(), "⛔ a filed piece was filed again");
        assert_eq!(d.collection_pieces_page("bears", 0, 10).1, 0);
    }

    /// Un-doing a fold step takes back everything it wrote: a new collection (and its place in the newest-first order),
    /// an owner's change to another, an asset's record, a picture added to an earlier record, a piece's filing and the
    /// pictures only that step named. The records are byte for byte what they were, so a re-fold of the same blocks
    /// reaches the same directory.
    #[test]
    fn undoing_a_step_takes_back_a_collection_an_assets_record_and_its_place_among_the_pieces() {
        let mut d = Directory::new();
        let alice = owner(1);
        let (cover1, cover2, art1, art2, art4) = (png(1, 100), png(2, 120), png(21, 100), png(22, 100), png(24, 100));
        // before the step: one collection with one filed piece (pictures held), and a record that names no picture yet
        let mut setup = d.begin_step();
        assert!(d.apply_entry_journaled(&collection_entry("apes", "Apes", "", Some(&cover1)), alice, &mut setup));
        assert!(d.apply_asset_record_journaled(&asset_entry(1, alice, true, Some(&art1), Some(&art1)), &mut setup));
        assert!(d.apply_asset_filing_journaled(&filing(1, "apes"), &mut setup));
        assert!(d.apply_asset_record_journaled(&asset_entry(4, alice, true, Some(&art4), None), &mut setup));
        assert!(d.keep_pic(&cover1) && d.keep_pic(&art1));
        let snapshot = |d: &Directory| {
            (
                d.acc,
                d.log_len(),
                d.total(),
                d.collections_page(0, 10).1,
                d.collection_pieces_page("apes", 0, 10),
                d.resolve_collection("apes").cloned(),
                d.resolve_asset(&hex32(&[1u8; 32])).cloned(),
                d.resolve_asset(&hex32(&[4u8; 32])).cloned(),
            )
        };
        let before = snapshot(&d);
        // the step: a second collection, a change to the first (a new cover), a new piece filed, a picture added to the
        // earlier record, and that earlier record filed
        let mut step = d.begin_step();
        assert!(d.apply_entry_journaled(&collection_entry("bears", "Bears", "", None), alice, &mut step));
        assert!(d.apply_entry_journaled(&collection_entry("apes", "Great Apes", "renamed", Some(&cover2)), alice, &mut step));
        assert!(d.apply_asset_record_journaled(&asset_entry(2, alice, true, Some(&art2), Some(&art2)), &mut step));
        assert!(d.apply_asset_filing_journaled(&filing(2, "apes"), &mut step));
        assert!(d.apply_asset_record_journaled(&asset_entry(4, alice, true, Some(&art4), Some(&art4)), &mut step));
        assert!(d.apply_asset_filing_journaled(&filing(4, "bears"), &mut step));
        assert!(d.keep_pic(&cover2) && d.keep_pic(&art2) && d.keep_pic(&art4));
        assert_eq!((d.collection_pieces_page("apes", 0, 10).1, d.collection_pieces_page("bears", 0, 10).1), (2, 1), "CALIBRATION: the step wrote");
        assert_eq!(d.collections_page(0, 10).0.first().map(|c| c.handle.as_str()), Some("bears"), "CALIBRATION: newest first");
        d.undo_step(step);
        assert_eq!(snapshot(&d), before, "the un-done step left something behind");
        assert!(d.resolve_collection("bears").is_none() && d.resolve_asset(&hex32(&[2u8; 32])).is_none());
        assert_eq!(d.asset_art(&hex32(&[1u8; 32])), art1.as_slice(), "the piece written before the step keeps its picture");
        assert!(
            d.pic_bytes(&digest(&cover2)).is_empty() && d.pic_bytes(&digest(&art2)).is_empty() && d.pic_bytes(&digest(&art4)).is_empty(),
            "pictures only the un-done step named are let go"
        );
        // ⛔ the first cover's bytes came with an OLDER entry that this rewind does not carry back, so they were kept
        // when the change replaced them: the collection shows its first cover again at once, owing nothing
        assert!(d.pics_owed(8).is_empty(), "a rewound cover change left the collection without its earlier cover");
        assert_eq!(d.collection_cover("apes"), cover1.as_slice());
        // and a refill's replay is when bytes nothing names are let go
        d.drop_unnamed_pics();
        assert_eq!(d.collection_cover("apes"), cover1.as_slice(), "a named picture survives the sweep");
    }

    /// A signature over an entry covers the picture it names: the same entry naming another cover is a different
    /// message, and an entry with no picture signs exactly what it signed before pictures existed.
    #[test]
    fn an_entrys_signed_message_covers_the_picture_it_names() {
        let with = collection_entry("apes", "Apes", "", Some(&png(1, 100)));
        let mut swapped = with.clone();
        swapped.pic = Some(digest(&png(2, 100)));
        assert_ne!(dir_entry_msg(&with), dir_entry_msg(&swapped), "⛔ a cover can be swapped under its owner's signature");
        let bare = name_entry("alice", "addrA");
        assert_eq!(
            dir_entry_msg(&bare),
            dir_register_msg(KIND_NAME, &canon_name("alice"), "addrA", "", ""),
            "an entry with no picture signs what it always signed"
        );
    }
}
