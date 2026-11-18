// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::asset_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `asset_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::asset_tx::*;
use serde::{Deserialize, Serialize};

/// TEST — ⭐ §BR-14: pay `c`'s creation fee the way the creator's wallet does: [`fund_creation_fee_note_for_test`] then
/// [`creation_fee_leg_for_test`]. Returns the timestamp to continue from.
#[cfg(test)]
pub(crate) fn pay_creation_fee_for_test(
    a: &mut crate::node::Node,
    peers: &mut [&mut crate::node::Node],
    c: &mut AssetCreateTx,
    tag: u64,
    ts: u64,
) -> u64 {
    let ts = fund_creation_fee_note_for_test(a, peers, c, tag, ts);
    c.fee = creation_fee_leg_for_test(a, c, tag);
    ts
}

/// TEST — lay the USDm note `tag`'s fee witness spends (worth the price + F + a remainder) on `a`, graft it on every peer,
/// and fold it past the fold depth on every party. Returns the timestamp to continue from.
#[cfg(test)]
pub(crate) fn fund_creation_fee_note_for_test(
    a: &mut crate::node::Node,
    peers: &mut [&mut crate::node::Node],
    c: &AssetCreateTx,
    tag: u64,
    ts: u64,
) -> u64 {
    let w = creation_fee_witness_for_test(c, tag);
    let (note, cm) = crate::node::tests::note_of_witness_for_test(&w);
    let (funding, _) = a.carry_notes_in_a_block_for_test(ts, &note);
    for p in peers.iter_mut() {
        assert!(
            matches!(p.ingest_block(funding.clone(), ts + 1), crate::relay::RelayOutcome::Added(_)),
            "PRECONDITION: a peer grafts the creation fee's funding block"
        );
    }
    // 20 ms steps: at the production fold depth (32) the wait is 34 blocks, which must stay below a fixture's next fixed
    // timestamp (the node pins lay their creation at 5,000 after funding at 1,000)
    let ts = crate::node::tests::produce_past_the_fold(a, peers, ts + 20, 20);
    assert!(a.holds_record_with_cm(&cm), "PRECONDITION: the creator's node holds the fee note's folded record");
    ts
}

/// TEST — `c`'s fee leg over the note `tag`'s witness spends (funded and folded on `a`): the bond-validity carrier (out0 =
/// exactly the price into [`creation_burn_cm`] of `c`, out1 = change, F welded), the one-step membership from `a`'s record,
/// the change note and a change clue. Two creations built with one `tag` spend ONE note (one nullifier).
#[cfg(test)]
pub(crate) fn creation_fee_leg_for_test(a: &crate::node::Node, c: &AssetCreateTx, tag: u64) -> CreationFee {
    let price = c.creation_price();
    let w = creation_fee_witness_for_test(c, tag);
    let (_note, cm) = crate::node::tests::note_of_witness_for_test(&w);
    let (carrier, cms, nf, lc) =
        usdm_decider::whir_rec_block::prove_bond_validity_carrier_with_commit_bytes(&w, price).expect("the fee burn proves");
    assert_eq!(cms[0], creation_burn_cm(&c.asset_id, price), "CALIBRATION: the burn destroys exactly this creation's price");
    let leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w).expect("a well-formed witness states its leaf");
    let (membership_carrier, membership_tip) =
        crate::node::tests::one_step_membership_for_test(a, &cm, leaf, nf, w.lc_blind).expect("the fee note's member step builds");
    let mut change_note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    change_note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cms[1]));
    let mut change_clue = vec![0u8; crate::peg_in_tx::OWNER_CLUE_MAX];
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/test/creation-change-clue/v1");
    h.update(&tag.to_le_bytes());
    h.update(&c.asset_id);
    h.finalize_xof().fill(&mut change_clue);
    CreationFee {
        nullifier: crate::spend_frontier::leaf_to_cm_bytes(nf),
        leaf_commit: crate::spend_frontier::leaf_to_cm_bytes(lc),
        carrier,
        membership_carrier,
        membership_tip,
        change_note,
        change_clue,
    }
}

pub fn apply_chain_asset_spend(node: &mut crate::node::Node, blob: &[u8]) -> AssetApply {
    match crate::chain_object::unframe(blob) {
        Some((crate::chain_object::Class::AssetSpend, payload)) => apply_asset_spend(node, payload),
        _ => AssetApply::NotAsset,
    }
}

pub(crate) fn asset_spend_refusal(
    node: &crate::node::Node,
    t: &AssetSpendTx,
    door: crate::respend::MemberDoor,
) -> Option<&'static str> {
    if !t.value_is_conserved() {
        return Some(
            "the carrier does not conserve value in one asset for the notes this transfer carries",
        );
    }
    // DB-213c: a transfer's membership proof is bound to the nullifier it retires.
    let Some(binder) = t.nullifier_digest() else {
        return Some("the spent note's nullifier is not a canonical digest");
    };
    // §19: a spend carrying its MEMBER LEG (the tuple present) is judged by the one shared dispatcher — what the wallet
    // sends now (no spend path of the wallet names a record); the one-step form the node's own objects and the
    // fixtures still build is judged as before. Parity with the SAT-bond door, which takes both in its tip slot.
    let verdict = if t.member_tuple.is_empty() {
        node.membership_carrier_verdict(
            &t.membership_carrier,
            t.leaf_commit,
            binder,
            t.tip_prev,
            t.tip_root,
            t.tip_acc,
            t.named_record,
            door,
        )
    } else {
        node.asset_member_leg_verdict(&t.membership_carrier, &t.member_tuple, t.leaf_commit, binder, door)
    };
    match verdict {
        crate::node::MemberVerdict::Member => {}
        // Admit only (the Fold door never waits): an otherwise-valid carrier whose record is not folded here yet.
        crate::node::MemberVerdict::Pending => return Some(ASSET_SPEND_PENDING),
        crate::node::MemberVerdict::Refused => {
            return Some("the spent note's membership does not verify against this node's own record roots")
        }
    }
    // ⛔⛔⛔ REFUSE ONLY A *POSITIVE* SPENT VERDICT — NEVER `Unprovable`.
    //
    // This asked `node.nullifier_is_unspent(&t.nullifier)`, a bool, and treated anything but a proof of
    // absence as "already spent". MEASURED: a node answers `Unprovable` for EVERY nullifier — including
    // ones nobody has ever spent — from the moment it produces or grafts its first block, because the
    // produce path adopts the block's committed sparse root in O(1) and deliberately holds NO copath index
    // (mirroring it cost ~2.5 MB/block and was reverted). So this gate refused **every honest transfer on
    // every node that had ever produced**, while reading like a double-spend check.
    //
    // ⭐ THE POSITIVE PROOF OF ABSENCE IS NOT THIS NODE'S TO GIVE. It rides the TRANSACTION — the
    // recursive absence carrier plus the per-tag sparse copaths the spender self-builds — and is judged at
    // the pool door, the same authority every spend class on this chain is judged by. By the time this
    // runs, the block's nullifier lane has been verified and `chain_object::wrapper_binds_object` has
    // already required `t.nullifier` to BE in that lane, so the burn is proven to travel.
    //
    // What stays here is the half this node CAN answer: when its index does describe the committed tree, a
    // provably SPENT note is refused outright. That is redundancy, not the authority — and redundancy that
    // fires only on a positive proof can never refuse honest money.
    // ([[feedback_borrow_proven_chains_no_rederiving]]: a spent note is refused by the SET, Zcash's shape.)
    // ⛔ THE TWO DOORS ASK TWO DIFFERENT SETS (2026-10-04). At ADMIT (the pool) the question is "spent, or about to be":
    // `sparse_spent_verdict` includes the pre-fold spends of every UNFOLDED block, so a pooled transfer never races a
    // block that already carries its input. At the FOLD the question is "spent BEFORE this block in canonical order":
    // the fold-point set S_b (the view plus the admitted sets of earlier steps) — never the unfolded blocks, which
    // include THIS block (its own lane names this very nullifier) and its siblings. Asking the admit question at the
    // fold refused every asset spend at its own fold, on every node alike.
    // ROOT-LAYER: the asset spend's refusal predicate is the ONE site both doors call; the door picks the set here.
    // MEASURED (before): `a_wrapped_note_minted_to_a_holder_is_moved_and_a_node_fed_only_blocks_retires_it` — GREEN
    //   2026-10-02 15:59, RED after `spent_by_an_unfolded_block` joined `sparse_spent_verdict` (DB-353 landing 2):
    //   "[objects-fold] ⛔ DB-274 P4b: 2 note(s) of class object(s) refused … at their fold" on A and B, no membership
    //   or conservation refusal logged — the only unlogged arm is this one.
    // MUST-STAY-GREEN: the DB-358 first-spender pins (`db358_r4_…`, `db358_r5_…`: a tag an EARLIER step admitted is
    //   still refused here through S_b), `db224_a_fill_whose_inputs_…` (the admit door unchanged), the rogue second-mint
    //   census pin (the publisher door is the admit door).
    // cons: none — one set read either way.
    // §18.14: a claim tag is asked the same question: the set admits one claim of a slot.
    let already_spent = t.tags().iter().any(|tag| match door {
        crate::respend::MemberDoor::Admit => node.sparse_spent_verdict(tag) == crate::nf_sparse::SpentVerdict::Spent,
        crate::respend::MemberDoor::Fold => node.fold_point_spent_set().holds(tag),
    });
    if already_spent {
        return Some("the note is already spent");
    }
    None
}

pub(crate) fn apply_asset_spend(node: &mut crate::node::Node, payload: &[u8]) -> AssetApply {
    let Some(t) = AssetSpendTx::decode(payload) else {
        return AssetApply::SpendRefused("the payload is not a transfer");
    };
    // The FOLD door: an asset transfer applies at its block's canonical fold (the objects step), so its named record must
    // be folded before this block — one verdict on every node, whatever each holds.
    if let Some(why) = asset_spend_refusal(node, &t, crate::respend::MemberDoor::Fold) {
        // A transfer a block carried and the fold refused leaves the payer's input unspent and the payee unpaid, and said nothing:
        // a DeFi order then waited a whole run for an exact note that never came (MEASURED 2026-11-08, launch_trade.py).
        // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only; no note, tag, amount or owner.
        eprintln!("[asset-apply] ⛔ a transfer a block carried was refused at the fold: {why}");
        return AssetApply::SpendRefused(why);
    }
    // DIGITAL-CASH-PRIVACY-REVIEWED: a count of notes only; no note, tag, amount or owner.
    eprintln!("[asset-apply] a transfer applied at the fold ({} output note(s) credited)", t.notes.len());
    // Every gate passed. Credit both notes; each output's owner is filed from the object's own clue
    // (`chain_object::object_owner_clue_records`, DB-273 §19.6 L3) — no account target.
    let h = node.tip_height();
    for n in t.notes.iter() {
        node.record_note_payload(h, n);
    }
    // ⛔ NO RE-STAGE (2026-10-04, DB-274 P4b): this apply runs at the FOLD of the block that already carries the
    // transfer and its notes — that block is the justification (§BA is satisfied by the carrier itself). Re-staging
    // re-carried the object in this node's next block. Law: `Node::apply_fold_class_object`.
    AssetApply::Spent
}

/// ⭐ THE FOLD-SIDE DOOR for assets (creation, mint, transfer) — run by `Node::apply_fold_class_object` at the carrying
/// block's CANONICAL fold, so every node registers the same assets and credits the same supply from the same bytes in the
/// same order. That is what makes a token an asset rather than a row in one web server's memory.
///
/// ⛔ §BR-14 (2026-10-28): creation and mint MOVED here from the graft loop (DB-223 Q7's shape for the transfer). A creation
/// now spends a note (its fee burn), and a spend's membership is a state-dependent verdict that only the canonical order makes
/// one verdict on every node; a refused creation's notes then leave the row and its tags retire nothing. The mint follows
/// the creation it depends on into the same canonical order (a mint folded before its creation is refused without burning
/// its issuance right — the tag is unadmitted — and the held mint returns to the pool, DB-389).
///
/// Total and deliberately dumb: bytes that are not an asset object return `NotAsset` untouched, so it can
/// be called on every transaction with no type tag on the wire.
pub fn apply_chain_asset_object(node: &mut crate::node::Node, blob: &[u8]) -> AssetApply {
    // ⛔ THE CLASS IS READ WHERE IT IS FRAMED, NEVER GUESSED FROM A DECODE. A bare `postcard` decode is
    // not injective across types, so "a creation cannot be mistaken for a transfer" is a property of
    // today's field lists and not of the format — the same reasoning `apply_chain_dex_object` had to
    // retire. A framed blob is judged by its own class; an unframed one is not an asset object.
    if let Some((class, payload)) = crate::chain_object::unframe(blob) {
        // ⭐ EVERY ASSET CLASS IS JUDGED BY ITS OWN FRAME. Only `AssetSpend` was handled here, so a FRAMED
        // creation or mint fell through to the unframed `try-each-decode` below and failed to decode —
        // which is why `Class::AssetCreate` and `Class::AssetMint` had no publisher a user could reach:
        // anything they emitted in the one canonical encoding was unreadable at the door.
        match class {
            crate::chain_object::Class::AssetSpend => return apply_asset_spend(node, payload),
            crate::chain_object::Class::AssetCreate => {
                let Some(c) = AssetCreateTx::decode(payload) else {
                    return AssetApply::CreateRefused("the payload is not a creation");
                };
                // ⛔ THE NODE'S OWN REGISTRY, NOT A CALLER'S. This took a `&mut DsolRegistry` from
                // whoever called it, and the only holder was the WEB SERVER's in-memory one — so a
                // creation registered in one process and nowhere else, and two nodes held two
                // registries. It is chain state: every node applies the same bytes and reaches the
                // same root.
                // ⭐ §BR-14: the fee burn decides FIRST, at the Fold door — a creation whose burn does not verify registers
                // nothing, credits nothing, and its tags retire nothing.
                if let Some(why) = node.creation_fee_refusal(&c, crate::respend::MemberDoor::Fold) {
                    return AssetApply::CreateRefused(why);
                }
                // ⛔ A-F34: a creation that carries its supply is refused WHOLE unless that supply is its creator's and its
                // note opens to the amount in this asset (the mint's own questions, asked of the same value a mint
                // would be). Decided before anything is written: no asset is registered beside a supply nobody may mint.
                if !c.supply_authorised(&crate::pqauth::MlDsaVerifier) {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only; no note, key or amount.
                    eprintln!("[asset-apply] ⛔ a creation a block carried was refused at the fold: its supply is not its creator's");
                    return AssetApply::CreateRefused("the creation's supply is not signed by the asset's creator, or its note does not open to the amount in this asset");
                }
                let root = node.register_dsol_asset(&c.descriptor());
                // §12.6: the asset's name, picture and collection become its directory record in this block's journaled
                // directory step, so every node names and pictures the asset from the chain (first creation of an id only).
                let _ = node.record_asset_at_fold(&c);
                // The burn's change is the carrier's `out1`, filed from the object's own clue
                // (`chain_object::object_owner_clue_records`).
                let h = node.tip_height();
                node.record_note_payload(h, &c.fee.change_note);
                // ⭐ A-F34 — AND THE WHOLE SUPPLY, IN THE SAME STEP. The asset exists because this very object is being
                // applied, so nothing is asked of a registry witness; the creation's lane retired the issue right
                // (`AssetCreateTx::own_nullifiers`), so no mint of this asset can ever follow. The note's owner is filed
                // from the clue the creator signed (`chain_object::object_owner_clue_records`).
                if let Some(m) = c.as_mint() {
                    node.record_note_payload(h, &m.note);
                    // §12.6: the collection the creator files this asset under (their signature covers the handle)
                    let _ = node.file_asset_at_fold(&m);
                    // §14.3: and its whole supply, in the same journaled step (a pool's tokenomics read it)
                    let _ = node.supply_asset_at_fold(&m);
                    // DIGITAL-CASH-PRIVACY-REVIEWED: an event only; no note, amount, tag or owner.
                    eprintln!("[asset-apply] an asset was created with its supply at the fold (one supply note credited)");
                }
                return AssetApply::Created(root);
            }
            crate::chain_object::Class::AssetMint => {
                let Some(m) = AssetMintTx::decode(payload) else {
                    return AssetApply::MintRefused("the payload is not a mint");
                };
                // ⛔⛔⛔ TWO GATES, AND ONLY THE SECOND ONE EXISTED. `credit_is_authorised` proves the
                // carrier opens the note to the claimed amount — it stops a minter lying about what it
                // RECEIVES. It never asked whether that minter MAY mint, so anyone could issue unlimited
                // supply of anyone's asset and mint the same NFT twice (MEASURED:
                // `the_same_nft_cannot_be_minted_twice_or_it_is_not_unique`).
                if !m.creator_authorised(&crate::pqauth::MlDsaVerifier) {
                    return AssetApply::MintRefused(
                        "the mint is not signed by the key that created this asset",
                    );
                }
                if !m.credit_is_authorised() {
                    // Refused BEFORE any credit — the carrier must open the note to the authorised
                    // amount in this asset, or the minter chooses what it receives.
                    return AssetApply::MintRefused(
                        "the note does not open to the authorised amount in this asset",
                    );
                }
                // ⭐⭐⭐ AND THE ASSET MUST ACTUALLY EXIST ON THIS CHAIN.
                //
                // ⛔ THE TWO GATES ABOVE BIND THE MINTER TO A DESCRIPTOR AND TO NOTHING ELSE. They check
                // that the creator signed this descriptor and that the note opens to the authorised amount
                // in it — and both are true for a descriptor whose CREATION WAS NEVER PUBLISHED. Supply
                // would then exist for an asset no node has registered: the notes credit, they carry an
                // asset tag, and they circulate against a registry root that has never heard of them, so
                // the DEX quotes a token nobody can look up and a holder cannot prove what they hold.
                //
                // The node computes the leaf from the descriptor ITSELF and folds the minter's self-built
                // path to its own registry root, so a forged descriptor yields a different leaf and is
                // refused. This is what makes the registry authoritative rather than decorative.
                if !node.verify_token_membership(
                    &m.rebuilt_descriptor(),
                    &m.registry_path,
                    &m.registry_dirs,
                ) {
                    // A-F34: this refusal was SILENT, and it was the one that ate every second creation's mint on real
                    // nodes (the wallet sent no witness). Said now, as a transfer's refusal is.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only; no note, key or amount.
                    eprintln!("[asset-apply] ⛔ a mint a block carried was refused at the fold: its registry witness does not open the token registry");
                    return AssetApply::MintRefused(
                        "this asset is not in the chain's token registry — its creation was never published",
                    );
                }
                // DB-273 §19.6 L3: the note's owner is filed from the object's own clue
                // (`chain_object::object_owner_clue_records`), which the creator's signature covers — no account target.
                let h = node.tip_height();
                node.record_note_payload(h, &m.note);
                // §12.6: the collection the creator files this asset under (their signature above covers the handle),
                // written into this block's journaled directory step; a mint that names none files nothing.
                let _ = node.file_asset_at_fold(&m);
                // §14.3: and the asset's whole supply (an asset is minted once: its issue right is retired)
                let _ = node.supply_asset_at_fold(&m);
            // ⭐⭐⭐ §BA — STAGE THE OBJECT THAT JUSTIFIES THESE NOTES BESIDE THEM.
            //
            // The notes above ride this node's NEXT produced block through the staged-credit lane. On every
            // OTHER node they are notes from nowhere: under the constant-256 cover a peer resolves almost
            // none of a block's bodies, so "nothing to judge from" used to mean RECEIVED (§BA). The object
            // rides `Block::credit_set` with them, and the peer re-runs `chain_object::admissible` plus
            // `carried_note_payloads` on these exact bytes rather than taking the producer's word.
                // ⛔ NO RE-STAGE (2026-10-04): this apply runs for an object a BLOCK carried (graft or fold) — that block is
                // the justification; re-staging re-carried it. Law: `Node::apply_fold_class_object`.
                return AssetApply::Minted(m.amount);
            }
            _ => {}
        }
    }
    // ⛔ The legacy unframed try-each-decode is DELETED (§BR-14): every publisher frames its object, and an unframed creation
    // would be a creation with no fee door. An unframed blob is not an asset object.
    AssetApply::NotAsset
}
