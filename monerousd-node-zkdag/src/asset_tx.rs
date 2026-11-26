// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **AN ASSET IS A CHAIN OBJECT.** Creating a token or an NFT, and minting its supply, as transactions.
//!
//! ⛔ WHAT THIS FIXES, read out of live code 2026-09-04. `/api/tokens/create` compiled a contract, hashed
//! its descriptor into an asset id, and RETURNED JSON. No transaction, no node call, nothing published —
//! creating a token produced a DESCRIPTION of a token. `/api/nft/order` went through the identical arm, so
//! NFTs had the identical gap. And the registry those descriptors landed in lives in the WEB SERVER's
//! memory (`sovereign.rs`: `Arc<Mutex<DsolRegistry>>`), so two nodes held two registries. No route anywhere
//! minted token supply as notes, so a custom token could not be held, sent or traded at all.
//!
//! That is the project's root error a third and fourth time: a local computation returned as if it were a
//! state change. The DEX fill was the first, the six issuance routes the second.
//!
//! THE SHAPE, borrowed rather than re-derived: a spend is a transaction, and a block carries what is needed
//! to apply it. So creation is a transaction whose bytes every node applies identically, and a mint is a
//! transaction gated exactly as the wrapped mint already is — the one asset path in this codebase that is
//! provably sound, because `execute_wrapped_mint` requires the note's commitment to open to the AUTHORIZED
//! amount IN THE AUTHORIZED ASSET before it credits anything.
//!
//! THREE PROPERTIES THIS FILE ENFORCES, each because its absence is a way to steal:
//!   1. AN ASSET ID IS RECOMPUTED, NEVER TRUSTED. The id is a hash of the descriptor, so a node re-derives
//!      it from the bytes and refuses a mismatch. Otherwise anyone could claim another asset's identity and
//!      mint into it.
//!   2. A MINT BINDS THE NOTE TO (AMOUNT, ASSET). Without it the caller chooses what it receives — the peg
//!      hole of 2026-08-26, where a note sealed for 1e6 was credited under an authorised mint of 100.
//!   3. AN NFT IS INDIVISIBLE. Amount is exactly one, refused otherwise, or an NFT is just a token with a
//!      confusing name.

use serde::{Deserialize, Serialize};

/// What kind of asset a creation declares. Kept as our own enum rather than reusing `DsolKind` on the wire,
/// so the CONSENSUS encoding cannot drift when the registry's presentation enum gains a variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetKind {
    Token,
    Nft,
}

impl AssetKind {
    pub fn as_dsol(self) -> crate::dsol::DsolKind {
        match self {
            AssetKind::Token => crate::dsol::DsolKind::Token,
            AssetKind::Nft => crate::dsol::DsolKind::Nft,
        }
    }
}




/// TEST — the creator's fee-burn witness for `c` (tag-seeded keys): out0 = exactly the price into `c`'s burn opening.
#[cfg(test)]
pub fn creation_fee_witness_for_test(c: &AssetCreateTx, tag: u64) -> usdm_decider::whir_rec_block::SpendValidityWitness {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block::{NoteOwner, SpendValidityWitness, PROTOCOL_FEE_ATOMIC};
    let price = c.creation_price();
    let value_in = price + PROTOCOL_FEE_ATOMIC + 70_000_000;
    SpendValidityWitness {
        value_in,
        owner: NoteOwner::from_test_key(lanes_of(&[0xc4ea, tag, 1, 2])),
        value_out: value_in - PROTOCOL_FEE_ATOMIC,
        fee: PROTOCOL_FEE_ATOMIC,
        lc_blind: lanes_of(&[0xc4ea, tag, 3, 3]),
        out0_value: price,
        out0_opening: creation_burn_opening(&c.asset_id),
        out1_value: value_in - PROTOCOL_FEE_ATOMIC - price,
        out1_opening: lanes_of(&[0xc4ea, tag, 4, 4]),
    }
}

/// TEST — `c`'s fee leg with a REAL carrier and placeholder membership bytes: what a blob-only door (`admissible`) judges.
/// Membership is the fold's, so a pin of the stateless door needs no funded note.
#[cfg(test)]
pub fn fee_leg_carrier_only_for_test(c: &AssetCreateTx, tag: u64) -> CreationFee {
    let w = creation_fee_witness_for_test(c, tag);
    let (carrier, cms, nf, lc) =
        usdm_decider::whir_rec_block::prove_bond_validity_carrier_with_commit_bytes(&w, c.creation_price()).expect("the fee burn proves");
    let mut change_note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    change_note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cms[1]));
    CreationFee {
        nullifier: crate::spend_frontier::leaf_to_cm_bytes(nf),
        leaf_commit: crate::spend_frontier::leaf_to_cm_bytes(lc),
        carrier,
        membership_carrier: vec![1],
        membership_tip: vec![1],
        change_note,
        change_clue: vec![0x5c; crate::peg_in_tx::OWNER_CLUE_MAX],
    }
}

/// ⭐ THE ID OF THE ASSET A KEY CREATED: `derived_id` of the descriptor `(kind, symbol, name, logo)` under the creator id
/// of `creator_pubkey`, with the contract body every asset of that kind, symbol and name compiles to. An asset's id binds
/// its creator, so "this key created asset `id`" is this function's value equalling `id`, and nothing else: no registry
/// is read. ONE derivation for every door that asks it (a mint's `creator_authorised`, a pool's creator claim
/// `ion_pool_tx::IonCreatorAuth`).
#[must_use]
pub fn asset_id_of_creator(kind: AssetKind, symbol: &str, name: &str, logo: [u8; 32], creator_pubkey: &[u8]) -> [u8; 32] {
    AssetCreateTx {
        kind,
        symbol: symbol.to_string(),
        name: name.to_string(),
        logo, // finding A-F24: the digest the asset's identity binds, never a zero
        bytecode: crate::dsol::compile(
            match kind {
                AssetKind::Nft => crate::dsol::DsolKind::Nft,
                AssetKind::Token => crate::dsol::DsolKind::Token,
            },
            symbol,
            name,
        )
        .bytecode,
        creator: crate::pqauth::pubkey_id(creator_pubkey),
        asset_id: [0u8; 32],
        fee: CreationFee::default(),
        art: Vec::new(),
        supply: None,
    }
    .derived_id()
}

/// The creation of an asset, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetCreateTx {
    pub kind: AssetKind,
    pub symbol: String,
    pub name: String,
    /// The content-addressed logo digest the registry binds; zero when the creator supplied none.
    pub logo: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE compiled contract body, the fixed output
    /// of `dsol::compile`; it is the transaction itself and is released with it.
    pub bytecode: Vec<u8>,
    /// ⭐⭐⭐ THE CREATOR'S ID — `pqauth::pubkey_id(creator_pubkey)`, and the ONLY identity allowed to mint
    /// this asset's supply.
    ///
    /// ⛔⛔⛔ BEFORE THIS FIELD AN ASSET HAD NO OWNER AT ALL. `AssetMintTx` carried no signature and
    /// nothing tied a minter to the asset it was minting, so **anyone could mint unlimited supply of
    /// anyone's token, and the same NFT could be issued twice.** MEASURED by
    /// `node::tests::the_same_nft_cannot_be_minted_twice_or_it_is_not_unique`: a second mint under a
    /// DIFFERENT key, naming the identical `asset_id`, applied and credited. The only gate was
    /// `credit_is_authorised`, which proves the carrier opens the note to the claimed amount — it stops a
    /// minter lying about what it RECEIVES, and says nothing about whether it MAY mint.
    ///
    /// ⭐ IT IS BOUND INTO `derived_id`, so the creator cannot be swapped after the fact: changing it
    /// changes the asset's identity, and every node recomputes that identity rather than taking the claim.
    pub creator: [u8; 32],
    /// The creator's claim. RECOMPUTED by every node — see `derived_id`.
    pub asset_id: [u8; 32],
    /// ⭐⭐⭐ §BR-14 item 4 — THE CREATION FEE, PAID BY A REAL USDm BURN THE CREATION CARRIES. See [`CreationFee`].
    pub fee: CreationFee,
    /// ⭐ THE PICTURE ITSELF (spec `docs/IONSWAP-POOLS-SPEC-20261110.md` §12.6): the bytes whose digest is `logo`, or
    /// empty when the creator puts no picture on the chain. The asset's directory record (`directory::KIND_ASSET`)
    /// names it by digest and nodes keep the bytes by that digest (`Directory::keep_pic`), so a wallet, the marketplace
    /// and the explorer show the same picture with no card.
    /// ⛔ BOUND THREE WAYS, so it cannot be attached to another asset, swapped or dropped in flight: `decode` refuses a
    /// picture whose blake3 is not `logo` (which the asset's identity binds); the price the burn proves counts its
    /// kilobytes ([`Self::creation_price`]), so a creation whose picture was stripped no longer matches its own burn;
    /// and its size and format are the directory's (`TOKEN_ART_MAX` / `NFT_ART_MAX`, PNG / JPEG / WebP).
    /// ⛔ A CREATION IS NOT SIGNED BY THE CREATOR IT NAMES (anyone may pay to create the asset a creator's facts
    /// describe), so it carries nothing only the creator may decide. A picture is safe here because it can only be the
    /// TRUE one (it must hash to `logo`), whoever supplies it. Which collection a piece is filed under is the creator's
    /// to say, so it rides the creator-signed mint (`AssetMintTx::collection`), never the creation: found 2026-11-11,
    /// before any of it landed, that a `collection` field here let anyone front-run a creation for the price of one
    /// and file the piece wrongly, or under none, for ever.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant and paid for by the kilobyte in this creation's own burn.
    pub art: Vec<u8>,
    /// ⭐ FINDING A-F34 (2026-11-11) — THE ASSET'S WHOLE SUPPLY, MINTED BY THE CREATION ITSELF. See [`CreationSupply`].
    /// `None`: a creation that mints nothing (its supply is then a separate [`AssetMintTx`] with a registry witness).
    pub supply: Option<CreationSupply>,
}

/// What a creator signs for the supply its creation carries: the mint's own message under a domain of its own (so the
/// signature is no mint's and a mint's is not this), and the number of picture bytes the creation carries (see
/// [`CreationSupply`]: a copy of the creation that leaves the picture out does not verify).
#[must_use]
pub fn creation_supply_msg(asset_id: &[u8; 32], amount: u64, note_cm: &[u8], owner_clue_digest: &[u8; 32], collection: &str, art_len: usize) -> Vec<u8> {
    let mut m = b"MUSD/asset-create/supply/v1".to_vec();
    m.extend_from_slice(&asset_mint_msg(asset_id, amount, note_cm, owner_clue_digest, collection));
    m.extend_from_slice(&(art_len as u64).to_le_bytes());
    m
}

/// ⭐⭐⭐ FINDING A-F34 (lane goods, 2026-11-11) — AN ASSET IS CREATED WITH ITS WHOLE SUPPLY, IN ONE OBJECT.
///
/// WHAT WAS WRONG (measured on three real nodes, build c492d893, check `nft`): the shipped wallet created an asset and
/// then sent a separate mint. A mint proves "this asset exists on this chain" with a path in the token registry
/// (`AssetMintTx::registry_path`), which a node cannot serve (it holds the registry's peaks only) and the wallet never
/// built: it sent NONE. An empty path opens the registry only when the asset's leaf is itself a peak, that is when the
/// registry holds an ODD number of assets and nothing was created after it. So about every second creation, and any
/// creation another creation overtook, was refused its mint at the fold, silently, after its price was burned: the
/// creator paid and held nothing, and the wallet had been told PUBLISHED. The check had passed before because its asset
/// was the first on a fresh chain.
///
/// THE RULE: the creation carries the supply note, the carrier that opens it to the amount in this asset's own tag, the
/// note's owner clue, and the CREATOR's key and signature over [`creation_supply_msg`]: everything a mint signs (the
/// asset, the amount, the note, the clue, the collection) AND how many bytes of picture the creation carries. The fold
/// registers the asset and credits the supply in one step, and the creation retires the asset's issue right on its own
/// lane, so the supply is fixed for good. The
/// question "does this asset exist?" is never asked of a witness: the object that answers it is the one being applied.
/// A creation with supply does NOT name the asset's creation id on its lane (a creation without supply still does):
/// were it named, anyone could publish a supply-less creation of the same facts first and the creator's own creation
/// would lose that one tag and be refused. As it stands a creator's creation with supply lands whatever anyone else
/// created; a copy of it is refused by its fee note and by the issue right.
/// WHY THE SIGNATURE COUNTS THE PICTURE'S BYTES: a creation is not signed as a whole (anyone may pay for one), so
/// without that a stranger could lift the creator's signed supply into a creation of their own that leaves the picture
/// out, get it in first, and the creator's own creation would then be refused (the issue right is spent): the asset
/// would exist, supplied, with no picture on the chain. With the count in the signed message such a copy does not
/// verify; a copy that keeps the picture is the creator's own creation, paid for by somebody else.
///
/// AI RESISTANT: (a) checks every node makes: the hash that is the asset's id (it binds the creator's key), an
/// ML-DSA-65 signature, and the mint carrier's proof. A lying sender needs the creator's key to state any supply.
/// SAFE AT SCALE: one note, one carrier and one signature a creation, about 12 KB more than a creation alone; no term
/// in the assets that exist, in height or in the nodes that bond.
/// cons: a creation that carries its supply is about 12 KB larger (its carrier, a 1,952-byte key, a 3,309-byte
/// signature, one note); an asset can gain a second registry leaf if someone also pays for a supply-less creation of
/// it (bytes in the registry's log-sized state, paid by whoever does it; no supply, no record and no right change).
/// BORROWED: a token whose constructor mints its fixed supply in the deployment itself (the ERC-20 fixed-supply
/// pattern on Ethereum); an issuance with initial allocation defined in one etching (Bitcoin Runes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreationSupply {
    pub amount: u64,
    /// O1-FOOTPRINT-REVIEWED: ONE note payload (`PQ_NOTE_BYTES`, or its 64-byte carriage reference); `decode` refuses another width.
    pub note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: ONE mint-validity carrier (the fixed output of `prove_asset_mint_validity_bytes`).
    pub mint_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: at most `peg_in_tx::OWNER_CLUE_MAX` (the mint's own rule, run by `decode`).
    pub owner_clue: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: at most `ASSET_MINT_AUTH_BYTES_MAX` (the mint's own rule, run by `decode`).
    pub creator_pubkey: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: at most `ASSET_MINT_AUTH_BYTES_MAX` (the mint's own rule, run by `decode`).
    pub creator_sig: Vec<u8>,
    /// The collection the creator files the asset under (a canonical handle, or empty), inside the signed message.
    pub collection: String,
}

/// ⭐⭐⭐ §BR-14 item 4 — THE CREATION FEE IS A BURN INSIDE THE CREATION, decided at the carrying block's fold and credited to
/// the chain's four fee pools there.
///
/// ⛔ WHAT IT REPLACES (measured 2026-10-28): `/submit_asset_create` published a creation that paid NOTHING on chain, and the
/// web route's "fee" was a note plus a carrier proving the note opens to the price — nothing spent that note, so one note
/// paid for every creation, and the price never reached the pools (§12 item 4 named the fee "burned"; it was not even that).
///
/// THE SHAPE, borrowed: a fee is value the transaction's own input pays (Bitcoin: inputs − outputs; Zcash: the value balance),
/// and a burn with a public amount is the bond-validity spend the cash-out burn already uses (`PegOut`): the creator spends one
/// USDm note whose membership the note-membership carrier proves, `out0` (exactly the symbol's price,
/// [`crate::params::token_create_fee_atomic`]) is destroyed, `out1` returns as change, and the carrier's weld pays the flat
/// network fee F on top.
///
/// ⭐ BOUND TO THIS CREATION: `out0`'s commitment is [`creation_burn_cm`] — a public function of the creation's own derived id
/// and price — so a burn proven for one creation cannot be lifted onto another (the carrier binds `out0_cm`), and `out0` is
/// never credited anywhere (no block carries it), so nothing can spend it.
///
/// §9.6 (the creation is now a value-moving door — it parallels the cash-out burn's): (1) proof of work — the carrying block's,
/// at the block doors; (2) the object's own proofs — the bond-validity carrier (price + F, out0 bound to the id) at the pool door
/// ([`AssetCreateTx::fee_carrier_verifies`] in `chain_object::admissible`) and again at the fold, with membership at both
/// (`Node::creation_fee_refusal`, Admit at publish, Fold at apply); (3) value — the burn destroys `price`, the change is the
/// carrier's own `out1` (conservation in-circuit), nothing else is credited; (4) replay — the fee note's nullifier is the
/// object's own lane tag ([`crate::chain_object::object_own_nullifiers`]), refused by the spent set, and the creation's
/// one-time id beside it (DB-388); (5) bounded work — one carrier + one member step per creation, constant shape; (6) parity
/// with the cash-out burn: membership (Fold door), the same carrier verify, the same F weld, change filed under its clue — the
/// custodian tally is the peg-out's own (a release of reserve), which a creation does not move.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreationFee {
    /// The spent USDm note's nullifier (canonical 32-byte digest) — the object's own lane tag.
    pub nullifier: [u8; 32],
    /// The membership cross-bind `P(P(leaf, nf), lc_blind)` the carrier and the member step both bind (DB-363).
    pub leaf_commit: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE bond-validity carrier, the fixed output of
    /// `prove_bond_validity_carrier_with_commit_bytes`; released with the transaction.
    pub carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note-membership step carrier; released with the transaction.
    pub membership_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — the fixed one-step tip; released with the transaction.
    pub membership_tip: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note payload of `PQ_NOTE_BYTES` (or its 64-byte carriage
    /// reference), the carrier's `out1`.
    pub change_note: Vec<u8>,
    /// The change note's OLI clue (non-empty, at most `peg_in_tx::OWNER_CLUE_MAX`), filed from the object.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `peg_in_tx::OWNER_CLUE_MAX` — `decode` refuses anything larger.
    pub change_clue: Vec<u8>,
}

/// The opening of a creation's destroyed fee output: a public function of the creation's derived id, so every node recomputes
/// [`creation_burn_cm`] and a burn is bound to exactly one creation.
#[must_use]
pub fn creation_burn_opening(asset_id: &[u8; 32]) -> crate::spend_frontier::Digest4 {
    let mut pre = Vec::with_capacity(32 + 32);
    pre.extend_from_slice(b"USDMD-ASSET-CREATION-FEE-BURN-v1");
    pre.extend_from_slice(asset_id);
    crate::spend_frontier::cm_bytes_to_leaf(crate::hash::Hash32::hash(&pre).as_bytes())
}

/// The commitment the creation's fee burn MUST destroy: `asset_note_cm(price, USDm, creation_burn_opening(id))`.
#[must_use]
pub fn creation_burn_cm(asset_id: &[u8; 32], price: u64) -> crate::spend_frontier::Digest4 {
    usdm_decider::whir_rec_block::asset_note_cm(
        price,
        usdm_decider::whir_rec_block::USDM_ASSET_TAG,
        creation_burn_opening(asset_id),
    )
}

/// ⭐ THE PRICE OF CREATING ONE ASSET, from its kind and the size of the picture it puts on the chain (§12.6): the kind's
/// price ([`crate::params::asset_create_fee_atomic`]) plus the directory's price for each started kilobyte of picture
/// every node will keep (`dir_entry_tx::DIR_KB_FEE_ATOMIC`). ONE function: the gate that charges it
/// ([`AssetCreateTx::creation_price`]), the route that quotes it and the wallet that shows it all read it here, so they
/// cannot disagree.
#[must_use]
pub fn creation_price_of(nft: bool, art_len: usize) -> u64 {
    let kb = u64::try_from(art_len.div_ceil(1024)).unwrap_or(u64::MAX);
    crate::params::asset_create_fee_atomic(nft).saturating_add(crate::dir_entry_tx::DIR_KB_FEE_ATOMIC.saturating_mul(kb))
}

impl AssetCreateTx {
    /// The FRAMED blob — the one form this object travels in, so a peer knows WHICH rule to judge it by.
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::AssetCreate, &self.encode())
    }

    /// The id this descriptor MUST have. A node computes it and compares; it never takes the claim.
    /// Byte-for-byte the derivation `/api/tokens/create` already used, so an id minted before this change
    /// and an id minted after are the same id for the same token.
    pub fn derived_id(&self) -> [u8; 32] {
        let kstr = match self.kind {
            AssetKind::Token => "token",
            AssetKind::Nft => "nft",
        };
        let mut pre: Vec<u8> = Vec::new();
        pre.extend_from_slice(b"USDMD-DSOL-ASSET-v2");
        pre.extend_from_slice(kstr.as_bytes());
        pre.extend_from_slice(&(self.symbol.len() as u32).to_le_bytes());
        pre.extend_from_slice(self.symbol.as_bytes());
        pre.extend_from_slice(&(self.name.len() as u32).to_le_bytes());
        pre.extend_from_slice(self.name.as_bytes());
        pre.extend_from_slice(&crate::hash::Hash32(self.logo).to_hex().into_bytes());
        // ⭐ THE CREATOR IS PART OF THE IDENTITY. Two creators may pick the same ticker and name; they are
        // different assets, and neither can mint into the other's.
        pre.extend_from_slice(&self.creator);
        pre.extend_from_slice(&self.bytecode);
        // ⭐ A-F114 — UNIQUE BY CONSTRUCTION (from the network upgrade, `params::CANON_LIVE`): the id also hashes this
        // creation's FEE NULLIFIER, a real note's and so unique by the note rule, so no two creations can ever share an id
        // and no set is needed to refuse a second creation of one (the MMR registry, `dsol::DsolRegistry`, holds only its
        // peaks and cannot). BORROWED: Ethereum's CREATE address, `hash(sender, nonce)`. Off, the id is unchanged.
        if crate::params::canon_live() {
            pre.extend_from_slice(b"FEE-NF");
            pre.extend_from_slice(&self.fee.nullifier);
        }
        *crate::hash::Hash32::hash(&pre).as_bytes()
    }

    /// The tag every note of this asset carries. Derived from the id, so it is unique per asset rather than
    /// per symbol — two creators may pick the same ticker and they are still different assets.
    pub fn asset_tag(&self) -> [u64; 3] {
        usdm_decider::whir_rec_block::wrapped_asset_tag(&self.asset_id)
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Refuses rather than guesses. A blank symbol, an over-long name, empty bytecode, or an id that does
    /// not match its own descriptor is not an asset creation.
    pub fn decode(bytes: &[u8]) -> Option<AssetCreateTx> {
        let a: AssetCreateTx = crate::chain_object::decode_exact(bytes)?;
        if a.symbol.trim().is_empty() || a.symbol.len() > 32 || a.name.len() > 128 {
            return None;
        }
        if a.bytecode.is_empty() {
            return None;
        }
        if a.derived_id() != a.asset_id {
            return None; // a claimed identity that is not this descriptor's own
        }
        // §12.6: the facts become a directory record whose `name` field is unit-separator packed, so neither may hold one
        if a.symbol.contains('\u{1f}') || a.name.contains('\u{1f}') {
            return None;
        }
        // §12.6: a picture is this asset's own (its digest is the `logo` the identity binds), of a kind and size the
        // chain keeps; a collection is named by its canonical handle or not at all
        let art_max = match a.kind {
            AssetKind::Nft => crate::directory::NFT_ART_MAX,
            AssetKind::Token => crate::directory::TOKEN_ART_MAX,
        };
        if !crate::directory::art_ok(&a.art, art_max) {
            return None;
        }
        if !a.art.is_empty() && *crate::hash::Hash32::hash(&a.art).as_bytes() != a.logo {
            return None; // a picture that is not the one this asset's identity binds
        }
        // §BR-14: a creation that carries no burn is not a creation — the fee is part of the object, never optional.
        let f = &a.fee;
        if f.carrier.is_empty() || f.membership_carrier.is_empty() || f.membership_tip.is_empty() {
            return None;
        }
        if f.change_clue.is_empty() || f.change_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX {
            return None; // the change is filed under exactly one bounded clue
        }
        // a whole note (pool form) or its 64-byte reference (carriage form) — anything else misaligns the block's notes
        if f.change_note.len() != crate::cover::PQ_NOTE_BYTES && f.change_note.len() != 64 {
            return None;
        }
        if crate::spend_frontier::note_cm_of(&f.change_note).is_none()
            || crate::spend_frontier::cm_bytes_to_root(&f.nullifier).is_none()
            || crate::spend_frontier::cm_bytes_to_root(&f.leaf_commit).is_none()
        {
            return None; // non-canonical digests came from no prover
        }
        // A-F34: a supply is a mint's words and obeys a mint's own structural rules (one rule set, the mint's decode),
        // and its note is a whole note or its carriage reference, like the change beside it
        if let Some(m) = a.as_mint() {
            if AssetMintTx::decode(&m.encode()).as_ref() != Some(&m) {
                return None;
            }
            if m.note.len() != crate::cover::PQ_NOTE_BYTES && m.note.len() != 64 {
                return None;
            }
        }
        Some(a)
    }

    /// A-F34 — THE MINT THIS CREATION'S SUPPLY IS: the same object a separate mint would be, built from the creation's
    /// own facts and the supply's words (no registry witness: the creation is the asset's existence). Every check a mint
    /// answers is asked of THIS value, so the two paths cannot drift apart. `None` when the creation mints nothing.
    #[must_use]
    pub fn as_mint(&self) -> Option<AssetMintTx> {
        let s = self.supply.as_ref()?;
        Some(AssetMintTx {
            asset_id: self.asset_id,
            kind: self.kind,
            amount: s.amount,
            note: s.note.clone(),
            mint_carrier: s.mint_carrier.clone(),
            owner_clue: s.owner_clue.clone(),
            creator_pubkey: s.creator_pubkey.clone(),
            creator_sig: s.creator_sig.clone(),
            symbol: self.symbol.clone(),
            asset_name: self.name.clone(),
            registry_path: Vec::new(),
            registry_dirs: Vec::new(),
            logo: self.logo,
            collection: s.collection.clone(),
        })
    }

    /// A-F34 — IS THE SUPPLY THE CREATOR'S, AND DOES ITS NOTE OPEN TO THE AMOUNT IN THIS ASSET? The three questions the
    /// gossip door asks of a mint (`chain_object::admissible`): SAT is issued only by mining; the key the asset's id
    /// binds signed this exact supply ([`creation_supply_msg`]: the mint's words and this creation's picture length);
    /// the carrier opens the note to the amount under this asset's tag. `true` for a creation that mints nothing.
    /// Judged from the object's own bytes, at the gossip door, the publishing door and again at the fold.
    #[must_use]
    pub fn supply_authorised(&self, v: &dyn crate::pqauth::PqVerifier) -> bool {
        let (Some(s), Some(m)) = (self.supply.as_ref(), self.as_mint()) else {
            return true;
        };
        let Some(cm) = crate::spend_frontier::note_cm_of(&s.note) else {
            return false;
        };
        let msg = creation_supply_msg(
            &self.asset_id,
            s.amount,
            &crate::spend_frontier::leaf_to_cm_bytes(cm),
            &crate::oli::owner_clue_digest(&s.owner_clue),
            &s.collection,
            self.art.len(),
        );
        m.asset_id != crate::satoshi::asset_id()
            && m.asset_tag() != crate::satoshi::asset_tag()
            // the key is the creator's: the asset's id binds `creator`, and the id is this descriptor's own
            && self.asset_id == self.derived_id()
            && crate::pqauth::pubkey_id(&s.creator_pubkey) == self.creator
            && v.verify(&s.creator_pubkey, &msg, &s.creator_sig)
            && m.credit_is_authorised()
    }

    /// The tags this creation retires on its lane: its fee note's nullifier, and EITHER the asset's creation id (a
    /// creation that mints nothing: a second creation of the asset is refused) OR the asset's issue right (a creation
    /// with its supply: the supply is fixed, and nobody's supply-less creation of the same facts can take the tag the
    /// creator's own creation needs; see [`CreationSupply`]). ONE list for the publisher, the graft door and the fold.
    #[must_use]
    pub fn own_nullifiers(&self) -> Vec<[u8; 32]> {
        let id = self.derived_id();
        let right = if self.supply.is_some() { issue_right_nf(&id) } else { crate::peg::one_time_id_nf(crate::peg::ONE_TIME_ASSET_CREATE, &id) };
        vec![right, self.fee.nullifier]
    }

    /// The notes this creation carries, in order: ONE list for the publisher (`Node::publish_asset_create`) and for
    /// the wrapper binding every node re-derives from the object's bytes (`chain_object::carried_note_payloads`).
    /// - A creation that mints nothing plants the asset's issue right (a note of no value whose commitment is derived
    ///   from the asset's id) and carries its fee burn's change.
    /// - A creation WITH its supply carries the change and the supply note, and plants NO issue right: it retires the
    ///   right's tag on its own lane ([`Self::own_nullifiers`]), so the right would be a note nobody can ever use.
    ///
    /// ⛔ A-F34, MEASURED 2026-11-11 by `af34_assets_created_with_their_supply_are_minted_on_the_peer_whatever_the_
    /// registry_holds`: while a creation with its supply still planted the right, a stranger's supply-less creation of
    /// the same facts (a creation is not signed) put that one commitment on the chain first, and the pool's replay
    /// rule (`Node::tx_notes_already_on_chain`: a transaction whose note the chain already carries is a replay)
    /// answered the creator's own creation `AlreadySettled`. The creator could then never issue through the wallet.
    /// The replay rule is right; the note was the defect.
    ///
    /// SCALE: two or three notes a creation, whatever the bonded set, the assets created or the height.
    /// AI RESISTANT (b, behind the conservation the spend carriers prove): the list is a pure function of the object's
    /// own bytes, so a producer that carries any other note for a creation is refused by the byte-exact binding.
    #[must_use]
    pub fn carried_notes(&self) -> Vec<Vec<u8>> {
        let mut notes = Vec::with_capacity(2);
        if self.supply.is_none() {
            notes.push(issue_right_note(&self.derived_id()));
        }
        notes.push(self.fee.change_note.clone());
        if let Some(s) = &self.supply {
            notes.push(s.note.clone());
        }
        notes
    }

    /// The price this creation must burn: a pure function of its KIND ([`crate::params::asset_create_fee_atomic`]; the
    /// symbol stopped pricing it on 2026-11-10, see that function).
    /// §12.6: plus the directory's own price for each started kilobyte of the picture every node will keep
    /// (`dir_entry_tx::DIR_KB_FEE_ATOMIC`, 0.01 USDm): a token with an 8 KB logo 0.58 USDm, an NFT with a 24 KB picture
    /// 0.29 USDm, an NFT with none 0.05 USDm. A gigabyte of pictures costs a spammer at least 10,485 USDm, the same as
    /// any other directory byte.
    #[must_use]
    pub fn creation_price(&self) -> u64 {
        creation_price_of(matches!(self.kind, AssetKind::Nft), self.art.len())
    }

    /// The directory record the fold of this creation writes (`directory::KIND_ASSET`): the facts, and the picture's
    /// DIGEST when this creation carries the picture's bytes (the bytes themselves are kept apart, by that digest:
    /// `Directory::keep_pic`). A later creation of the same asset that carries the picture adds it to a record that
    /// had none (`Directory::apply_asset_record`). The collection is filed by the mint, never here.
    #[must_use]
    pub fn dir_record(&self) -> crate::directory::DirEntry {
        let hex = |b: &[u8; 32]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
        crate::directory::DirEntry {
            kind: crate::directory::KIND_ASSET,
            key: hex(&self.asset_id),
            address: hex(&self.creator),
            name: crate::directory::asset_facts_field(matches!(self.kind, AssetKind::Nft), &self.symbol, &self.name, &self.logo),
            topic: String::new(),
            pubkey: Vec::new(),
            sig: Vec::new(),
            pic: (!self.art.is_empty()).then_some(self.logo), // `decode` holds blake3(art) == logo
        }
    }

    /// ⭐ §BR-14 — the STATELESS half of the fee gate: the bond-validity carrier proves the creator spends the note named by
    /// (`nullifier`, `leaf_commit`), destroys exactly [`Self::creation_price`] into [`creation_burn_cm`] of THIS creation,
    /// returns the rest as `change_note`'s commitment, and pays the flat network fee. Membership (state) is the node's
    /// (`Node::creation_fee_refusal`).
    #[must_use]
    pub fn fee_carrier_verifies(&self) -> bool {
        let f = &self.fee;
        let (Some(nf), Some(lc), Some(change)) = (
            crate::spend_frontier::cm_bytes_to_root(&f.nullifier),
            crate::spend_frontier::cm_bytes_to_root(&f.leaf_commit),
            crate::spend_frontier::note_cm_of(&f.change_note),
        ) else {
            return false;
        };
        let price = self.creation_price();
        usdm_decider::verify_bond_validity_carrier_with_commit_bytes(
            &f.carrier,
            creation_burn_cm(&self.asset_id, price),
            change,
            nf,
            price,
            lc,
            usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC,
        )
    }

    /// The registry entry this creation becomes on every node that applies it.
    pub fn descriptor(&self) -> crate::dsol::DsolContract {
        crate::dsol::DsolContract {
            id: crate::hash::Hash32(self.asset_id),
            version: 2,
            kind: self.kind.as_dsol(),
            symbol: self.symbol.clone(),
            name: self.name.clone(),
            verified: false,
            logo: crate::hash::Hash32(self.logo),
        }
    }
}

/// A supply mint: `amount` of `asset_id`, credited as ONE note whose commitment the carrier opens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetMintTx {
    pub asset_id: [u8; 32],
    pub kind: AssetKind,
    pub amount: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note payload, `PQ_NOTE_BYTES`.
    pub note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE mint-validity carrier, the fixed output of
    /// `prove_asset_mint_validity_bytes`; released with the transaction.
    pub mint_carrier: Vec<u8>,
    /// ⭐ DB-273 §19.6 L3 — THE CREDITED NOTE'S OWNER: its OLI clue (`omr::Clue` bytes, non-empty, at most
    /// `peg_in_tx::OWNER_CLUE_MAX`), never a static `(bucket, ek)`. Its digest is inside [`asset_mint_msg`], so the
    /// creator's ML-DSA signature covers it: a relay that replaces or strips it breaks the signature on every node.
    /// Every node files the note from this field (`chain_object::object_owner_clue_records`).
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `peg_in_tx::OWNER_CLUE_MAX` — `decode` refuses anything
    /// larger, and it is released with the transaction.
    pub owner_clue: Vec<u8>,
    /// ⭐⭐⭐ THE CREATOR'S ML-DSA-65 PUBLIC KEY. Every node recomputes `pubkey_id` from it and rebuilds the
    /// asset's identity; a mint whose key does not reproduce `asset_id` is minting into someone else's
    /// asset and is refused.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant ASSET_MINT_AUTH_BYTES_MAX — `decode` refuses
    /// anything larger, and it is released with the transaction.
    pub creator_pubkey: Vec<u8>,
    /// ML-DSA-65 signature over [`asset_mint_msg`]. Re-verified at apply on every node — nothing trusted.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant ASSET_MINT_AUTH_BYTES_MAX — `decode` refuses
    /// anything larger, and it is released with the transaction.
    pub creator_sig: Vec<u8>,
    /// The asset's symbol and name, restated so a node can REBUILD `derived_id` and check the creator
    /// without looking anything up. ⛔ A registry lookup would need a per-asset map, which is a growth
    /// axis; a self-contained object needs none.
    pub symbol: String,
    pub asset_name: String,
    /// ⭐⭐⭐ THE REGISTRY MEMBERSHIP PATH — proof that this asset was actually CREATED on this chain.
    ///
    /// ⛔ WITHOUT IT, SUPPLY CAN EXIST FOR AN ASSET NO NODE HAS EVER REGISTERED. The gate below rebuilds
    /// the descriptor from this mint's own fields and checks the creator's signature over it, which binds
    /// the minter to the descriptor — and to nothing else. A creator who never published the creation
    /// still mints: the notes credit, they carry an asset tag, and they circulate against a registry root
    /// that has never heard of them. The DEX would then quote an asset nobody can look up.
    ///
    /// The node computes the leaf from the descriptor ITSELF and folds this path to its own registry root,
    /// so a forged descriptor yields a different leaf and is refused. Self-built by the minter from the
    /// PUBLIC creation stream (creations are public chain objects), never served by one party.
    ///
    /// O1-FOOTPRINT-REVIEWED: bounded by crate::dsol::MMR_MAX_PEAKS — one sibling per mountain level, and
    /// a mountain range over a u128 count is at most that deep. It rides with the transaction and is
    /// released with it; nothing retains it.
    pub registry_path: Vec<crate::spend_frontier::Digest4>,
    /// The left/right side at each level of `registry_path`, same length.
    /// O1-FOOTPRINT-REVIEWED: bounded by crate::dsol::MMR_MAX_PEAKS — one bool per path level.
    pub registry_dirs: Vec<bool>,
    /// ⛔ FINDING A-F24 (2026-11-11) — THE PICTURE DIGEST THE ASSET'S IDENTITY BINDS (`AssetCreateTx::logo`; zero when the
    /// creator bound none), restated like `symbol` and `asset_name` so a node can REBUILD `derived_id`.
    ///
    /// WHAT WAS WRONG (read in this file, then pinned RED): a mint had no such field, and `creator_authorised` and
    /// `rebuilt_descriptor` rebuilt the asset's identity with a ZERO logo. `derived_id` binds the logo, so for any asset
    /// created WITH a picture the rebuilt id was not the asset's id and every node refused the mint, after the creation
    /// had already burned its price: the creator paid and held nothing, and the asset could never have supply. Every
    /// NFT made in the studio and every token launched with a picture went that way. Nothing saw it because every
    /// check and pin created assets with no picture.
    /// It needs no place in the signed message: it is inside `asset_id`, which the signature covers, so a mint stating
    /// another digest rebuilds another id and is refused.
    pub logo: [u8; 32],
    /// ⭐ SPEC §12.6 — THE COLLECTION THIS ASSET IS FILED UNDER: a collection's canonical handle, or empty. The mint is
    /// the ONE object of an asset that only its creator can make (its signature below covers this field through
    /// [`asset_mint_msg`]) and that happens once (it retires the asset's issue right), so the creator says it here,
    /// once, and nobody else can. The directory keeps it only when that collection exists at this mint's fold and its
    /// owner is this creator (`Directory::apply_asset_filing`).
    pub collection: String,
}

/// The largest the creator's key + signature may be. `decode` refuses above it, so one mint can never
/// occupy unbounded pool weight.
pub const ASSET_MINT_AUTH_BYTES_MAX: usize = 16 * 1024;

/// ⭐⭐⭐ THE ISSUANCE RIGHT — the ONE thing an asset's creation plants and its mint spends, so an asset
/// can be issued EXACTLY ONCE and its supply is whatever that single issuance says.
///
/// ⛔⛔⛔ §AT CLOSED *WHO* MAY MINT AND NOT *HOW OFTEN*. MEASURED after the creator gate landed:
/// `creator_again=Minted(1)` — the creator re-issued the same NFT, so the token was not unique and a
/// token's supply had no cap at all. **Authorisation answers who; it never answers how many times.**
///
/// ⭐ IT IS A NOTE, AND THE MINT SPENDS IT. The creation carries this commitment as an output note, so it
/// enters the unspent tree like any credit; the mint retires it with the ORDINARY DELETION TRANSITION
/// (§AQ) — `fold(cm, copath) == old_root ∧ fold(EMPTY, copath) == new_root`. A second mint has no note
/// left to delete and cannot build the transition. Infinite mint is closed by the chain's own spend
/// authority, with NO per-asset state and therefore no growth axis.
///
/// ⛔ TWO EARLIER SHAPES FAILED, recorded so they are not retried:
///  1. **A RAW NULLIFIER ON THE TX LANE.** That lane's admission gate is spend-shaped and demands a
///     deletion transition; a tag for a note that was never planted has none. MEASURED:
///     `[asset-mint] REFUSED … (NullifierWitnessRejected)`. The gate was right — the RIGHT WAS MISSING.
///  2. **BINDING THE ISSUANCE NOTE'S COMMITMENT INTO `asset_id`.** Circular: `asset_id` <- `issue_cm` <-
///     the note's commitment <- the asset TAG <- `asset_id`. This construction runs the arrow the other
///     way — the commitment is derived FROM the id — so there is no cycle.
///
/// ⭐ A REPLAYED CREATION PLANTS THE SAME COMMITMENT, and one commitment is only ever credited once
/// (`crediting_the_same_note_commitment_twice_credits_it_once`), so creating an asset twice still yields
/// exactly one right.
#[must_use]
pub fn issue_right_cm(asset_id: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(32 + 32);
    pre.extend_from_slice(b"USDMD-ASSET-ISSUE-RIGHT-v1");
    pre.extend_from_slice(asset_id);
    *crate::hash::Hash32::hash(&pre).as_bytes()
}

/// Z1 (2026-09-22): the NULLIFIER that retires the issuance right — derivable from the object, like the
/// right itself, so `chain_object::wrapper_binds_object` can demand it in a mint's lane and the sparse
/// nullifier set refuses the second mint exactly as it refuses any double spend. A public one-shot
/// right needs no hidden nullifier: the asset's issuance is a public fact by construction.
#[must_use]
pub fn issue_right_nf(asset_id: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(32 + 32);
    pre.extend_from_slice(b"USDMD-ASSET-ISSUE-RIGHT-NF-z1");
    pre.extend_from_slice(asset_id);
    crate::cover::canonical_tag_of_hash(crate::hash::Hash32::hash(&pre).as_bytes())
}

/// That right as a NOTE the creation plants, at the wire width every note has.
#[must_use]
pub fn issue_right_note(asset_id: &[u8; 32]) -> Vec<u8> {
    let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    n[..32].copy_from_slice(&issue_right_cm(asset_id));
    n
}

/// ⭐ THE ONE MESSAGE a mint's signature covers — domain-separated and binding every field that decides
/// what is created: which asset, how much, the exact note credited, and (v2, DB-273 §19.6 L3) WHO the note is
/// filed for — `oli::owner_clue_digest` of the owner clue. A signature for one mint can never be replayed for
/// another amount, another asset, another note or another owner.
#[must_use]
/// §12.6: and, when the mint files its asset under a collection, the collection's handle after a separator, so a relay
/// cannot re-file a pooled mint. A mint that names no collection signs exactly what it signed before.
pub fn asset_mint_msg(asset_id: &[u8; 32], amount: u64, note_cm: &[u8], owner_clue_digest: &[u8; 32], collection: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + 32 + 8 + 32 + 32 + 12 + collection.len());
    m.extend_from_slice(b"USDMD-ASSET-MINT-v2");
    m.extend_from_slice(asset_id);
    m.extend_from_slice(&amount.to_le_bytes());
    m.extend_from_slice(note_cm);
    m.extend_from_slice(owner_clue_digest);
    if !collection.is_empty() {
        m.push(0u8);
        m.extend_from_slice(b"collection");
        m.extend_from_slice(collection.as_bytes());
    }
    m
}

impl AssetMintTx {
    /// The FRAMED blob — the one form this object travels in.
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::AssetMint, &self.encode())
    }

    pub fn asset_tag(&self) -> [u64; 3] {
        usdm_decider::whir_rec_block::wrapped_asset_tag(&self.asset_id)
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// ⭐⭐⭐ IS THIS MINT AUTHORISED BY THE ASSET'S OWN CREATOR?
    ///
    /// Two questions, and the old code asked neither:
    /// 1. **IS THE KEY THE CREATOR'S?** The asset's identity is rebuilt from `(kind, symbol, name, logo,
    ///    creator, bytecode)` and compared to the `asset_id` this mint names. A key that does not
    ///    reproduce that id belongs to a different asset — or to nobody.
    /// 2. **DID THAT KEY SIGN THIS EXACT MINT?** The signature covers the asset, the amount and the
    ///    credited note commitment, so it cannot be replayed for a larger amount or a different recipient.
    ///
    /// ⛔ SELF-CONTAINED BY DESIGN. Every node answers from the object's own bytes — no registry lookup,
    /// which would need a per-asset map and therefore a growth axis.
    #[must_use]
    /// The descriptor this mint claims to be minting — rebuilt from the mint's OWN fields, never taken
    /// from a caller. `creator_authorised` and the registry-membership gate both read it, so the identity
    /// the signature covers and the identity the registry is checked for are the same bytes by
    /// construction. Two derivations of one descriptor is exactly how a mint gets past one gate and not
    /// the other.
    pub fn rebuilt_descriptor(&self) -> crate::dsol::DsolContract {
        AssetCreateTx {
            kind: self.kind,
            symbol: self.symbol.clone(),
            name: self.asset_name.clone(),
            logo: self.logo, // finding A-F24: the digest the asset's identity binds, never a zero
            bytecode: crate::dsol::compile(
                match self.kind {
                    AssetKind::Nft => crate::dsol::DsolKind::Nft,
                    AssetKind::Token => crate::dsol::DsolKind::Token,
                },
                &self.symbol,
                &self.asset_name,
            )
            .bytecode,
            creator: crate::pqauth::pubkey_id(&self.creator_pubkey),
            asset_id: self.asset_id,
            fee: CreationFee::default(), // the descriptor only: the fee is not part of an asset's identity,
            art: Vec::new(),
            supply: None,
        }
        .descriptor()
    }

    pub fn creator_authorised(&self, v: &dyn crate::pqauth::PqVerifier) -> bool {
        let Some(cm) = crate::spend_frontier::note_cm_of(&self.note) else {
            return false;
        };
        if asset_id_of_creator(self.kind, &self.symbol, &self.asset_name, self.logo, &self.creator_pubkey) != self.asset_id {
            return false; // this key did not create this asset
        }
        v.verify(
            &self.creator_pubkey,
            &asset_mint_msg(
                &self.asset_id,
                self.amount,
                &crate::spend_frontier::leaf_to_cm_bytes(cm),
                &crate::oli::owner_clue_digest(&self.owner_clue),
                &self.collection,
            ),
            &self.creator_sig,
        )
    }

    pub fn decode(bytes: &[u8]) -> Option<AssetMintTx> {
        let m: AssetMintTx = crate::chain_object::decode_exact(bytes)?;
        // The same width the commitment reader (`note_cm_of`) needs — refused at the EARLIEST door rather
        // than at the one that would have read past the end of it.
        if m.amount == 0
            || m.note.len() < crate::spend_frontier::NOTE_CM_BYTES
            || m.mint_carrier.is_empty()
        {
            return None;
        }
        // ⛔ AN NFT IS ONE THING. A "quantity 5" NFT is a token wearing the wrong name, and every downstream
        // surface that treats it as unique would be wrong about it.
        if matches!(m.kind, AssetKind::Nft) && m.amount != 1 {
            return None;
        }
        // ⛔ AN UNAUTHORISED MINT IS NOT A MINT — refused at the wire, never left to a reader. The
        // bounds are the same protocol constant the fields declare.
        if m.creator_pubkey.is_empty()
            || m.creator_sig.is_empty()
            || m.creator_pubkey.len() > ASSET_MINT_AUTH_BYTES_MAX
            || m.creator_sig.len() > ASSET_MINT_AUTH_BYTES_MAX
        {
            return None;
        }
        // ⛔ DB-273 §19.6 L3 — A MINT NAMES ITS NOTE'S OWNER, or it is not a mint: a note filed for nobody is money no
        // seed restore finds. Bounded by the one clue width, so the pool weight stays a constant.
        if m.owner_clue.is_empty() || m.owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX {
            return None;
        }
        // §12.6: a collection is named by its canonical handle or not at all
        if !m.collection.is_empty() && !crate::directory::collection_handle_ok(&m.collection) {
            return None;
        }
        Some(m)
    }

    /// THE GATE THE WRAPPED MINT ALREADY PROVES. The note's commitment must open to THIS amount in THIS
    /// asset under the supplied carrier — otherwise the caller chooses what it receives, which is exactly
    /// the peg hole of 2026-08-26 where a note sealed for 1e6 was credited under an authorised mint of 100.
    pub fn credit_is_authorised(&self) -> bool {
        // The note's commitment, read by the ONE reader every credit door uses (`note_cm_of`): the
        // injective decode of the canonical 32-byte form every producer writes into `note[..32]`.
        // ⛔ §AG CLASS 9, TWICE OVER. This first read `DIGEST_LANES` raw little-endian u64s behind a
        // `< 32` guard — a 32..63-byte mint note PANICKED the door. The 2026-09-13 guard fix (`< 64`)
        // stopped the panic but kept a SECOND ENCODING of the commitment: a note the faucet / the fill /
        // the order book sealed (`leaf_to_cm_bytes` at the front, sealed bytes after) read as garbage
        // limbs here and could never open its own carrier. One consensus object, one encoding.
        let Some(cm) = crate::spend_frontier::note_cm_of(&self.note) else {
            return false;
        };
        usdm_decider::whir_rec_block::verify_asset_mint_validity_bytes(
            &self.mint_carrier,
            cm,
            self.amount,
            self.asset_tag(),
        )
    }
}

/// ⭐ THE CAP ON EITHER CARRIER A SPEND CARRIES, enforced in [`AssetSpendTx::decode`] — a blob above it is
/// REFUSED, never held. Both carriers are fixed-shape outputs (the asset-spend validity gate and the
/// one-step note-membership gate), so this is headroom over a constant, not a budget for growth; it keeps
/// two spends inside a tenth of the ≤1.8 MB bundle budget at any chain height.
pub const ASSET_SPEND_CARRIER_BYTES_MAX: usize = 262_144;

/// The fixed output arity of the asset-spend gate: one note in, TWO notes out. The owner list is one
/// entry per output, and `decode` refuses any other length.
pub const ASSET_SPEND_OUTPUTS: usize = 2;

/// ⭐⭐⭐ AN ASSET TRANSFER — the object that makes a token or an NFT SPENDABLE.
///
/// Until this existed a holder could be credited an asset and could never move it: `AssetApply` covered
/// CREATE and MINT only, and `prove/verify_asset_spend_validity_carrier_bytes` had ZERO callers. An asset
/// you cannot spend is not an asset.
///
/// ⛔⛔⛔ IT TAKES **TWO** CARRIERS, AND THAT IS NOT BELT-AND-BRACES.
/// `verify_asset_spend_validity_carrier_bytes` takes NO anchor root — its public bind is
/// `[DOMAIN, out0, out1, nullifier, leaf_commit]` and the membership copath is a FREE WITNESS. MEASURED in
/// `whir_rec_block::the_asset_spend_carrier_proves_no_membership_so_the_door_must_require_the_membership_carrier`:
/// the same note under two invented copaths yields byte-identical public values and both verify. The
/// validity carrier proves CONSERVATION and ONE ASSET; the note-membership carrier proves the note was
/// ever received; `leaf_commit` pins them to the same note. A door that asks only the first has admitted
/// a spend of a note nobody was ever paid.
///
/// ⭐ And the membership half must be anchored on state the NODE derives
/// (`Node::verify_membership_carrier_one_step` re-derives the record root and refuses a carried one that
/// disagrees) — never on a root read out of this transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetSpendTx {
    /// The two output note payloads, in the carrier's own order.
    /// O1-FOOTPRINT-REVIEWED: bounded by ASSET_SPEND_OUTPUTS — a fixed-length array, released with the tx.
    pub notes: [Vec<u8>; ASSET_SPEND_OUTPUTS],
    /// The spent note's nullifier — the burn the block's nullifier lane must carry, so every node retires
    /// the same note whether or not it ever held this transaction's bytes.
    pub nullifier: [u8; 32],
    /// `Poseidon(Poseidon(leaf, binder), blind)` (DB-363) — the ONE value both carriers name, which is what makes them
    /// a statement about the same note rather than two unrelated facts; `blind` is the spender's secret, so the value
    /// joins the spend to no public leaf.
    pub leaf_commit: crate::spend_frontier::Digest4,
    /// The asset-spend VALIDITY carrier: conservation, and one asset through every leg.
    /// O1-FOOTPRINT-REVIEWED: bounded by ASSET_SPEND_CARRIER_BYTES_MAX — `decode` refuses above it.
    pub validity_carrier: Vec<u8>,
    /// The note-MEMBERSHIP carrier: the note was received. Without it the copath above is free.
    /// O1-FOOTPRINT-REVIEWED: bounded by ASSET_SPEND_CARRIER_BYTES_MAX — `decode` refuses above it.
    pub membership_carrier: Vec<u8>,
    /// ⭐ §19 (2026-10-28) — THE MEMBER LEG'S TUPLE (`member_transition::MEMBER_TUPLE_BYTES`): with it, `membership_carrier`
    /// is the ring-anchored member leg (DB-223 Q7, the path every send carries), cross-bound to this spend's nullifier and
    /// blinded leaf commit with ZERO outputs (the validity carrier binds the outputs). The record-naming one-step bind
    /// below (`named_record`, the three tips) is RETIRED at this door: a spend without the tuple is refused.
    #[serde(default)]
    pub member_tuple: Vec<u8>,
    /// The record ADDRESS the membership proof names, so the node derives that record's root ITSELF.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a record address, not a note identity — a record carries the fixed
    /// 256-note cover, so this names a SPAN and never which item inside it. Byte-for-byte the same field
    /// an ordinary send already carries; this introduces no handout the send path did not already make.
    pub named_record: u64,
    /// The membership transition the carrier attests. Carried for arity only: the node RE-DERIVES the
    /// root from `named_record` and refuses a carried value that disagrees.
    pub tip_prev: crate::spend_frontier::Digest4,
    pub tip_root: crate::spend_frontier::Digest4,
    pub tip_acc: crate::spend_frontier::Digest4,
    /// ⭐ DB-273 §19.6 L3 — EACH OUTPUT'S OWNER: its OLI clue, one per output in the carrier's order, never a static
    /// `(bucket, ek)`. Every node files the outputs from these (`chain_object::object_owner_clue_records`), so a peer that
    /// never pooled the transfer still finds them for their owners. A zero-value output carries a clue too (the wallet's
    /// throwaway `void` locator), so the clue count never reveals a zero value.
    /// Named residual (the transfer class, DB-273 §19.6): these are bound by the object's bytes, not yet by the validity
    /// carrier; lane-recursion's `owner_clues_digest` public-bind closes the relay re-frame.
    /// O1-FOOTPRINT-REVIEWED: bounded by ASSET_SPEND_OUTPUTS entries of `peg_in_tx::OWNER_CLUE_MAX` — `decode` refuses
    /// any other count or width.
    pub owner_clues: Vec<Vec<u8>>,
    /// ⭐ §18.14 — `Some`: the carrier also proves this tag as `claim(key, d)` (DB-329's law) and the tag rides the nullifier lane, so the SET decides a device slot's claim as it does for a USDm note.
    /// Wallets send every transfer in this shape, an ordinary one claiming `(lc_blind, 0)`, so no transfer reads as a slot claim. `None`: the plain carrier the node's own objects use.
    pub slot_tag: Option<[u8; 32]>,
}

impl AssetSpendTx {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// The FRAMED blob — the only form this object travels in, so a peer knows WHICH rule to judge these
    /// bytes by. ⭐ ONE DEFINITION, the sibling of `order_fill_tx::OrderFillTx::wire` and
    /// `bridge_credit_tx::BridgeCreditTx::wire`: the framing used to be spelled inline at each call site,
    /// which is how a class tag drifts from the object it names.
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::AssetSpend, &self.encode())
    }

    /// Refuses rather than guesses. A spend with one carrier, an over-cap carrier, a short note, a zero
    /// depth, the sentinel nullifier, or an owner list that is not one entry per output is not a spend.
    pub fn decode(bytes: &[u8]) -> Option<AssetSpendTx> {
        let t: AssetSpendTx = crate::chain_object::decode_exact(bytes)?;
        if t.validity_carrier.is_empty() || t.membership_carrier.is_empty() {
            return None; // ⛔ ONE carrier is never enough — see this type's doc
        }
        if t.validity_carrier.len() > ASSET_SPEND_CARRIER_BYTES_MAX
            || t.membership_carrier.len() > ASSET_SPEND_CARRIER_BYTES_MAX
        {
            return None; // refused BEFORE verification, so an oversize blob is never even opened
        }
        if t.notes.iter().any(|n| n.len() < crate::spend_frontier::NOTE_CM_BYTES) {
            return None;
        }
        // DB-273 §19.6 L3: one owner clue per output, each a real clue — an output filed for nobody is money no seed
        // restore finds, and a list that does not line up files a note under the wrong owner.
        if t.owner_clues.len() != ASSET_SPEND_OUTPUTS
            || t.owner_clues.iter().any(|c| c.is_empty() || c.len() > crate::peg_in_tx::OWNER_CLUE_MAX)
        {
            return None;
        }
        if t.nullifier == [0u8; 32] || t.slot_tag == Some([0u8; 32]) {
            return None; // the all-zero nullifier is the IMT sentinel and is never a real spend
        }
        Some(t)
    }

    /// The nullifiers this object retires: its input's, and a claim tag if it carries one.
    #[must_use]
    pub fn tags(&self) -> Vec<[u8; 32]> {
        std::iter::once(self.nullifier).chain(self.slot_tag).collect()
    }

    /// The output commitments, READ OFF THE NOTES THIS TRANSACTION CARRIES rather than declared beside
    /// them. ⭐ A declared commitment is a second encoding of the same fact, and a second encoding is how
    /// a note becomes creditable twice (the lane-B carriage defect, and §AI's whole class). Read exactly
    /// as every credit door reads it — `note_cm_of`, the injective decode of the canonical 32-byte form
    /// every producer writes at the front of a note.
    ///
    /// ⛔ §AG CLASS 9 (a byte buffer sized by a lane count) lived here as a raw `DIGEST_LANES`-lane walk
    /// behind a `< 32` guard — a 32..63-byte note PANICKED a consensus door, i.e. a remote crash. The
    /// guard-only fix left a second encoding behind; the shared reader is the fix in both directions.
    #[must_use]
    pub fn output_commitments(&self) -> Option<[crate::spend_frontier::Digest4; ASSET_SPEND_OUTPUTS]> {
        Some([
            crate::spend_frontier::note_cm_of(&self.notes[0])?,
            crate::spend_frontier::note_cm_of(&self.notes[1])?,
        ])
    }

    /// The nullifier as the DIGEST the carrier named, recovered from its canonical 32-byte form.
    ///
    /// ⛔⛔⛔ THIS IS THE INJECTIVE DECODE, NEVER `key_of`. Kill list §AI: `key_of` is a HASH — it maps
    /// arbitrary 32-byte IDS into the field, and a digest put through it is not that digest. The value
    /// here is a digest the spend carrier PRODUCED, so it round-trips through the canonical pair
    /// (`leaf_to_cm_bytes` out, `cm_bytes_to_root` back) exactly as the fill's burns do. Using the hash
    /// here made an honest transfer's carrier fail to verify — MEASURED, in this file, the day it was
    /// written. ⭐ ROOTS AND DIGESTS TAKE THE DECODE; IDS TAKE THE HASH, and only the call site knows
    /// which kind of 32 bytes it is holding.
    ///
    /// `None` when the bytes are not a canonical digest — such a value did not come from this chain, and
    /// there is no nullifier it "means".
    #[must_use]
    pub fn nullifier_digest(&self) -> Option<crate::spend_frontier::Digest4> {
        crate::spend_frontier::cm_bytes_to_root(&self.nullifier)
    }

    /// THE BLOB-ONLY HALF: conservation, one asset through every leg, and the outputs this transaction
    /// actually carries. ⛔ This is NOT the whole gate — it proves nothing about whether the spent note
    /// was ever received. The membership half is asked at the node, against state the node derived.
    #[must_use]
    pub fn value_is_conserved(&self) -> bool {
        let Some(cms) = self.output_commitments() else {
            return false;
        };
        let Some(nf) = self.nullifier_digest() else {
            return false; // not a canonical digest: it did not come from this chain
        };
        if let Some(tag) = self.slot_tag {
            let Some(tag1) = crate::spend_frontier::cm_bytes_to_root(&tag) else {
                return false;
            };
            return usdm_decider::whir_rec_block::verify_asset_slot_claim_bytes(&self.validity_carrier, cms[0], cms[1], nf, self.leaf_commit, tag1);
        }
        usdm_decider::whir_rec_block::verify_asset_spend_validity_carrier_bytes(
            &self.validity_carrier,
            cms[0],
            cms[1],
            nf,
            self.leaf_commit,
        )
    }
}

/// What a transaction blob turned out to be, once a node looked at its bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum AssetApply {
    /// Not an asset object — left entirely alone.
    NotAsset,
    /// The asset joined this node's registry; the registry root moved to this value.
    Created([u8; 32]),
    /// A creation refused, with the reason a node can act on.
    CreateRefused(&'static str),
    /// Supply credited: this many units of the asset, as one note.
    Minted(u64),
    /// A mint refused before anything was credited.
    MintRefused(&'static str),
    /// A TRANSFER applied: the spent note is burned by the block's nullifier lane and the two outputs are
    /// credited. This is what makes a token or an NFT spendable.
    Spent,
    /// A transfer refused BEFORE anything was credited or burned, with the reason a node can act on.
    SpendRefused(&'static str),
}

/// ⭐ THE GRAFT-SIDE ENTRY FOR THE TRANSFER CLASS — the seam `Node`'s block-apply loop calls, beside
/// `bridge_credit`, `liquidation`, `wrapped_asset_register` and `wrapped_mint`.
///
/// A transfer MOVES VALUE, so it must be applied on EVERY node that grafts the block and not only on the
/// one that happened to pool it. Reads the class itself and answers `NotAsset` for a blob of another
/// class, exactly as its sibling arms do, so no arm has to know the others exist.
///
/// ⛔ CREATE and MINT are deliberately NOT on this seam yet: they need the `DsolRegistry`, which is a
/// field of the same node, and neither has a publisher today (`Class::AssetCreate` and `Class::AssetMint`
/// have ZERO framing sites outside tests). Adding them here before anything emits them would be a door
/// onto an empty corridor — they join when a publisher does.
// CHAIN-PUBLISH-REVIEWED: the apply half, driven by the AssetSpend chain object at graft.

/// ⛔⛔⛔ THE TRANSFER DOOR — both halves of the gate, and the second half is the one that is easy to
/// forget.
///
/// 1. **CONSERVATION AND ONE ASSET** ([`AssetSpendTx::value_is_conserved`]) — over the output
///    commitments read off the notes THIS transaction carries, not a pair declared beside them.
/// 2. ⭐ **THE NOTE WAS EVER RECEIVED** — the note-membership carrier, anchored on roots this node
///    DERIVES from the record address the proof names. Without it the validity carrier's copath is a free
///    witness and a spender mints by inventing a tree (MEASURED — see [`AssetSpendTx`]'s doc).
/// 3. **IT IS NOT ALREADY SPENT** — asked of `Node::nullifier_is_unspent`, the one authority.
///
/// Refuses BEFORE anything is credited or burned. ⭐ The BURN itself is not applied here: it rides the
/// block's nullifier lane, which every node folds whether or not it ever held this transaction's bytes.
/// That is what the carriage rule in `chain_object::wrapper_binds_object` enforces — it refuses a
/// transfer whose nullifier is absent from that lane, because a burn that stays local never travels and
/// the note is spent again on every other node (MEASURED 2026-09-03, the maker's lot paid out twice).
// CHAIN-PUBLISH-REVIEWED: the apply half, driven by the AssetSpend chain object at graft — every node
// runs these same bytes from the block, and the burn travels in the block's own nullifier lane.
/// ⭐⭐⭐ THE TRANSFER DOOR'S THREE GATES, AS ONE FUNCTION BOTH SIDES CALL.
///
/// The APPLIER (every node, at graft) and the PUBLISHER (`Node::execute_asset_spend`, on the spender's
/// own node) must judge a transfer by the identical rule. Spelling it twice is this tree's most expensive
/// recurring defect — `MultiTail::for_row`, the ladder slot encoding, `nf_key` vs `key_of`, the sparse
/// spent leaf, and `prove_block_pow` found the same day. **A rule with two spellings has already drifted;
/// you just have not measured it yet.**
///
/// ⛔ THE PUBLISHER'S CHECK IS A COURTESY, NOT AN AUTHORITY. It exists so a spender does not put a doomed
/// transaction into the mempool and burn its stamp work. What DECIDES a transfer is this same function run
/// by every grafting node against ITS OWN state — never the submitting node's verdict
/// ([[feedback_always_trustless]]: self-verification decides whether a node ACCEPTS a transition, never
/// whether it HAPPENED).
///
/// `door` (DB-358 (1)): the publisher asks as `Admit`, so a transfer of a note whose record the fold has not placed
/// waits for the fold. Every node applying the block asks as `Fold` at the block's canonical fold, so the named record
/// must be folded before that block: the canonical order's verdict, the same on every node.
/// [`asset_spend_refusal`]'s one WAIT: the transfer is otherwise valid and its record is not folded on this node yet
/// (`MemberVerdict::Pending`) — a race the fold resolves, answered as a retry, never as a wrong submission.
pub const ASSET_SPEND_PENDING: &str = "the spent note's record is not folded on this node yet — retry after the fold";
