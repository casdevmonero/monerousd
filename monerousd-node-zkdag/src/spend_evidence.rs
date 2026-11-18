// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §22c — NATIVE SPEND EVIDENCE: every node verifies, itself, every spend a block states (audit F14, 2026-11-10).
//!
//! WHAT WAS MEASURED. A block's note, tag and member ledgers lay each spend's carrier from the carrier's BYTES: its
//! opened row, its round values, its challenges. Nothing in the block proof checks the carrier's own opening proof, so a
//! producer lays a "carrier" no wallet proved (a garbage commitment, zero rounds, one opened cell solved until the gate
//! reads zero) and the block verifies (`usdm-decider` pin
//! `settlement_delta::producer_forgery_tests::a_block_cannot_state_a_spend_whose_carrier_nobody_proved`, 2026-11-10 12:09).
//! Such a row can publish a note of any value (inflation) or any tag (a freeze). Checking every carrier's opening inside
//! the block proof costs about ten thousand Poseidon rows per carrier, up to 768 carriers a block: about 180 times
//! today's block proof. It is not buildable at block cadence.
//!
//! THE RULE, BORROWED. Bitcoin: a block is its header AND its transactions, and a node connects a block only after it
//! has validated every one of them (`ConnectBlock` / `CheckInputScripts`). Zcash: every full node verifies every
//! shielded proof. This chain already obeys it for every framed class (a credit, a bond, a fill is judged natively at
//! the block door by `chain_object::admissible`); the ordinary send was the one class judged by the aggregate alone.
//! Here the send joins them: the block's spend transactions ride beside it ([`crate::block::Block::tx_bodies`], the
//! gossip envelope), and a row that states a spend is admitted only when one of those transactions, verified HERE,
//! states exactly that row.
//!
//! WHAT IS EVIDENCE. [`spend_evidence_of`] runs the three proofs a send carries, on the transaction's own fields and
//! nothing of this node's state: the spend carrier (value, both outputs, the nullifier, the claim tag, the filing digest,
//! the clock), the member leg (the input is a leaf under the anchor the transaction names, cross-bound to this spend)
//! and the cover arm (every carried tag is a real nullifier of the spender's or a derived decoy). The anchor's place in
//! the chain's ring is a fact about the chain and is judged at the fold (`Node::member_anchors_at_fold`), where every
//! node holds the same ring.
//!
//! WHAT A ROW IS. A ledger block's rows hide which are spends. A node that holds the body and its cover key recomputes
//! the block's cover cells (`note_transition::ledger_cover_cells`) and its carried objects' cells; a row with a cell in
//! neither set states a spend. A spend's HEAD row (its two real outputs, its nullifier, its claim tag) must be one
//! evidenced transaction's exact tuple, filing digest and a clock at or before the ledger's; every other spend-stated
//! tag must belong to a transaction whose head row this same block states. So no output is credited without its
//! nullifier, no nullifier is burned without its outputs, and nothing rests on a label the producer chose.
//!
//! §9.6 (this narrows the block door `Node::preverify_block`; it admits nothing that door refused):
//! 1 PoW: unchanged, verified before this runs. 2 Proof: the three carriers of every stated spend, verified natively on
//! a miss; a hit is a prior TRUE verdict for byte-identical transaction bytes. 3 Value: a note cell is credited only as
//! a cover cell (no opening exists), an object's cell (judged by the object's own rule) or an output of an evidenced,
//! conserving spend whose nullifier the same row burns. 4 Replay: unchanged, the spent set. 5 Bounded work: at most
//! `BLOCK_FIXED_TX_COUNT` bodies a block (the envelope keeps only named ids), three constant-size verifies each on a
//! miss, one BLAKE3 pass each on a hit; the cache holds at most [`CAPACITY`] entries. 6 Parity with the tx door
//! (`Node::send_verdict` + `member_carrier_verdict`): its spend arm, member leg and cover arm are this function's three
//! verifies with the same inputs; its state checks (anchor in this node's ring NOW, clock reached NOW, the pool's own
//! rules) are not evidence about the transaction and are judged by the fold in the block's canonical place.
//!
//! JOINERS. A node that adopts a bundle did not see the adopted blocks' transactions; its state's validity rests on the
//! work above it (docs/JOIN-BY-WORK-SPEC-20261106.md states that limit). Every block it then receives live passes here.
//!
//! O1-FOOTPRINT-REVIEWED: the cache holds at most [`CAPACITY`] evidences of about 1.3 KB each (≈ 5.3 MiB), FIFO-evicted,
//! never a function of height. An evicted entry costs its next presentation three verifies.
//! cons: three native verifies per stated spend per node on first sight (the gossip tx door records what it already
//! verified, so a pooled spend costs none again); about 0.5 MB per stated spend per block hop on the envelope.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use crate::block::Block;
use crate::hash::Hash32;
use crate::mempool::PqTx;
use crate::note_transition::SpendTuple;
use crate::spend_frontier::Digest4;

/// What one transaction's own proofs establish, read from the transaction alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendEvidence {
    pub tx_id: Hash32,
    /// The spend's head row: both outputs, the nullifier, the membership leaf commitment and the claim tag.
    pub tuple: SpendTuple,
    /// The filing digest its spend carrier binds last (DB-351).
    pub filing_d: Digest4,
    /// The chain clock its spend carrier was proven under (`PqTx::clock_ms`).
    pub clock_ms: u64,
    /// The spend-tree root its member leg proves the input under. Whether the chain's ring holds it is the fold's verdict.
    pub anchor: Digest4,
    /// Its whole constant-width tag set, in carried order (row 0 the nullifier, row 1 the claim tag).
    pub tags: Vec<[u8; 32]>,
}

/// How many evidences the cache holds.
pub const CAPACITY: usize = 4096;
const KEY_DOMAIN: &[u8] = b"monerousd/spend-evidence/v1";

struct Cache {
    held: HashMap<[u8; 32], Arc<SpendEvidence>>,
    order: VecDeque<[u8; 32]>,
}

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Cache { held: HashMap::new(), order: VecDeque::new() }))
}

/// The cache key of an encoded transaction: every byte of it, so two bodies that differ anywhere are two questions.
fn body_key(body: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(KEY_DOMAIN);
    h.update(&(body.len() as u64).to_le_bytes());
    h.update(body);
    *h.finalize().as_bytes()
}

fn remember(key: [u8; 32], e: Arc<SpendEvidence>) {
    let Ok(mut c) = cache().lock() else { return };
    if c.held.insert(key, e).is_none() {
        c.order.push_back(key);
        while c.order.len() > CAPACITY {
            if let Some(old) = c.order.pop_front() {
                c.held.remove(&old);
            }
        }
    }
}

/// The fields of a send's evidence, read off the transaction with NO proof run: `None` for anything that is not a
/// two-output USDm send in its one encoding. Private: only [`spend_evidence_of`] (which then runs the proofs) and
/// [`record_verified_by_the_tx_door`] (whose caller ran them) build an evidence from it.
fn evidence_fields(tx: &PqTx) -> Option<SpendEvidence> {
    const PQ: usize = crate::cover::PQ_NOTE_BYTES;
    if tx.id != PqTx::content_id(&tx.blob) || crate::chain_object::unframe(&tx.blob).is_some() {
        return None; // a framed object is judged by its class rule at the block door, never as a send
    }
    if !tx.stake_notes.is_empty() || !tx.bond_notes.is_empty() {
        return None;
    }
    if tx.output_notes.len() != 2 * PQ || tx.nullifiers.len() != crate::cover::TX_FIXED_NULLIFIER_COUNT {
        return None;
    }
    let tuple = crate::node::Node::spend_tuple_of(tx)?;
    if tuple.tag1.iter().all(|b| *b == 0) {
        return None; // an all-zero row states no claim
    }
    let filing_d = crate::node::Node::tx_filing_d(tx)?;
    crate::note_transition::clock_hours(tx.clock_ms)?;
    let member = crate::member_transition::read_tuple(&tx.member_tuple)?;
    if !crate::member_transition::cross_binds(&member, &tuple) {
        return None; // a member leg that speaks for another spend
    }
    if !tx.nullifiers.iter().all(|t| crate::spend_frontier::cm_bytes_to_root(t.as_bytes()).is_some()) {
        return None;
    }
    Some(SpendEvidence {
        tx_id: tx.id,
        tuple,
        filing_d,
        clock_ms: tx.clock_ms,
        anchor: member.anchor,
        tags: tx.nullifiers.iter().map(|t| *t.as_bytes()).collect(),
    })
}

/// THE EVIDENCE OF ONE SEND, from the transaction alone: its fields, then its three proofs. Pure; reads no node state.
/// A body in tree form is refused here (it carries no carrier; its statement is TRUE only beside the root its block
/// door verified): see [`tree_evidence_of`].
#[must_use]
pub fn spend_evidence_of(tx: &PqTx) -> Option<SpendEvidence> {
    if is_tree_form(tx) {
        return None;
    }
    proofs_evidence(tx)
}

/// ⭐ MILESTONE 2 (`crate::agg_root`) — is this a body in TREE form? It carries NO carrier: its spend carrier is the
/// tree tag and the commitment of its own statement (36 bytes, [`tree_statement_commit`]), its member and cover carriers
/// are empty. Everything a peer needs to state it is in the fields a full send carries beside its carriers.
#[must_use]
pub fn is_tree_form(tx: &PqTx) -> bool {
    tx.blob.len() == 36 && tx.blob[..4] == crate::agg_root::TREE_TAG
}

/// The 32 bytes a tree-form body's blob ends with: a commitment to every field its statement is read from, so the id
/// (`PqTx::content_id(blob)`) names ONE payment. It binds nothing a proof relies on (the root proves the statement the
/// peer derives from the fields themselves); it keeps two payments from sharing an id.
#[must_use]
pub fn tree_statement_commit(tx: &PqTx) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/tree-form-statement/v1");
    for part in [&tx.output_notes[..], &tx.member_tuple[..], &tx.membership_leaf_commit[..]] {
        h.update(&(part.len() as u64).to_le_bytes());
        h.update(part);
    }
    h.update(&(tx.nullifiers.len() as u64).to_le_bytes());
    for t in &tx.nullifiers {
        h.update(t.as_bytes());
    }
    h.update(&tx.clock_ms.to_le_bytes());
    let clues = postcard::to_allocvec(&tx.note_clues).unwrap_or_default();
    h.update(&(clues.len() as u64).to_le_bytes());
    h.update(&clues);
    *h.finalize().as_bytes()
}

/// The statement of a send, as the tree takes it (`agg_root::PaymentStatement`): the arguments of the three carrier
/// checks [`proofs_evidence`] makes, derived from the same fields the same way. `None` for anything that is not a
/// two-output USDm send in its one encoding.
fn statement_of(tx: &PqTx, e: &SpendEvidence) -> Option<crate::agg_root::PaymentStatement> {
    let root = crate::spend_frontier::cm_bytes_to_root;
    Some(crate::agg_root::PaymentStatement {
        c0: root(&e.tuple.out0_cm)?,
        c1: root(&e.tuple.out1_cm)?,
        nf: root(&e.tuple.nullifier)?,
        lc: root(&e.tuple.leaf_commit)?,
        d: e.filing_d,
        t1: root(&e.tuple.tag1)?,
        fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC,
        hours: crate::note_transition::clock_hours(tx.clock_ms)?,
        member: crate::member_transition::read_tuple(&tx.member_tuple)?,
        tags: tx.nullifiers.iter().map(|t| root(t.as_bytes())).collect::<Option<_>>()?,
    })
}

/// ⭐ MILESTONE 2 — THE EVIDENCE OF ONE TREE-FORM SEND and the statement its block's root must prove. NO proof runs
/// here: every field check a full send meets does ([`evidence_fields`]), and the evidence is TRUE only once the block's
/// root verifies over this statement in its carried place ([`block_spends_are_evidenced`]), which is the only door that
/// admits a block carrying one. `None` for a body that is not tree form, whose blob is not its own statement's
/// commitment, or that carries a carrier after all.
#[must_use]
pub fn tree_evidence_of(tx: &PqTx) -> Option<(SpendEvidence, crate::agg_root::PaymentStatement)> {
    if !is_tree_form(tx)
        || tx.blob[4..] != tree_statement_commit(tx)
        || !tx.member_carrier.is_empty()
        || !tx.spend_or_decoy.is_empty()
        || !tx.membership_carrier.is_empty()
    {
        return None;
    }
    let e = evidence_fields(tx)?;
    let st = statement_of(tx, &e)?;
    Some((e, st))
}

/// ⭐ MILESTONE 2 — THE HOLDER'S CONVERSION: verify a FULL send exactly as [`spend_evidence_of`] does and return its
/// tree form (no carrier; the stamp re-ground for the new id) with the statement its leaf proves. `None` unless the
/// full send verifies. The holder keeps the full send: its leaf and its block's ledger are laid from the full carriers.
#[must_use]
pub fn tree_form_of(tx: &PqTx, stamp_bits: u32) -> Option<(PqTx, crate::agg_root::PaymentStatement)> {
    if is_tree_form(tx) || !tx.membership_carrier.is_empty() {
        return None;
    }
    let e = spend_evidence_of(tx)?;
    let st = statement_of(tx, &e)?;
    let mut tree = tx.clone();
    tree.member_carrier = Vec::new();
    tree.spend_or_decoy = Vec::new();
    tree.blob = crate::agg_root::TREE_TAG.to_vec();
    tree.blob.extend_from_slice(&tree_statement_commit(&tree));
    tree.id = PqTx::content_id(&tree.blob);
    tree.pow_stamp = 0;
    while tree.stamp_work() < stamp_bits {
        tree.pow_stamp = tree.pow_stamp.checked_add(1)?;
    }
    Some((tree, st))
}

/// ⭐ §14 THE BUNDLE RELAY — A PRODUCER'S CHECK OF ONE TAKEN MEMBER: does `tree` (the holder's tree-form body) state
/// exactly the payment `full` is, and does `full` verify? `full` must verify as [`spend_evidence_of`] requires (its three
/// carriers, which this producer's ledger will lay from), and `tree` must be byte for byte the tree form of `full` with the
/// holder's own stamp, which must meet `stamp_bits` here. Returns the statement the bundle's root must prove for it.
/// §9.6 (2) the carriers are verified here, by this node, never taken on the holder's word; (6) parity with
/// `Node::hold_for_aggregation`: the same verify and the same conversion, the stamp checked instead of ground.
#[must_use]
pub fn tree_form_matches(full: &PqTx, tree: &PqTx, stamp_bits: u32) -> Option<crate::agg_root::PaymentStatement> {
    if is_tree_form(full) || !full.membership_carrier.is_empty() || !is_tree_form(tree) {
        return None;
    }
    let e = spend_evidence_of(full)?;
    let st = statement_of(full, &e)?;
    let mut expected = full.clone();
    expected.member_carrier = Vec::new();
    expected.spend_or_decoy = Vec::new();
    expected.blob = crate::agg_root::TREE_TAG.to_vec();
    expected.blob.extend_from_slice(&tree_statement_commit(&expected));
    expected.id = PqTx::content_id(&expected.blob);
    expected.pow_stamp = tree.pow_stamp;
    if expected.stamp_work() < stamp_bits || postcard::to_allocvec(&expected).ok()? != postcard::to_allocvec(tree).ok()? {
        return None;
    }
    Some(st)
}

/// The three proofs of a send.
fn proofs_evidence(tx: &PqTx) -> Option<SpendEvidence> {
    let e = evidence_fields(tx)?;
    // 1. the spend carrier: value conserved into both recorded outputs, the nullifier, the leaf commitment, D, the claim
    //    tag and the clock: the statement the tx door verifies (`Node::send_verdict`'s spend arm)
    if !crate::note_transition::carrier_verifies_at(&tx.blob, &e.tuple, e.filing_d, tx.clock_ms) {
        return None;
    }
    // 2. the member leg: the input is a leaf under the anchor this transaction names, cross-bound above
    let member = crate::member_transition::read_tuple(&tx.member_tuple)?;
    if tx.member_carrier.is_empty() || !usdm_decider::member_path_gate::verify_member_path_carrier(&tx.member_carrier, &member) {
        return None;
    }
    // 3. the cover arm: every carried tag is a real nullifier of the spender's or a correctly derived decoy
    let tags: Vec<Digest4> = tx.nullifiers.iter().map(|t| crate::spend_frontier::cm_bytes_to_root(t.as_bytes())).collect::<Option<_>>()?;
    if tx.spend_or_decoy.is_empty() || !usdm_decider::nf_sparse_air::verify_spend_or_decoy_bytes(&tx.spend_or_decoy, &tags) {
        return None;
    }
    Some(e)
}

/// The evidence of an ENCODED transaction (`postcard(PqTx)`, one of a block's carried bodies), verified once per node:
/// a hit returns the evidence a prior presentation of the byte-identical body established; a refused body is verified in
/// full every time it is presented (only a success is cached).
#[must_use]
pub fn evidence_of_body(body: &[u8]) -> Option<Arc<SpendEvidence>> {
    let key = body_key(body);
    if let Some(e) = cache().lock().ok().and_then(|c| c.held.get(&key).cloned()) {
        return Some(e);
    }
    let tx = crate::chain_object::decode_exact::<PqTx>(body)?;
    // lane agg: a tree-form body by its fields alone — its evidence is TRUE only beside the root its block door verified
    // (`block_spends_are_evidenced`), which is the only door that admits a block carrying one
    let e = Arc::new(if is_tree_form(&tx) { tree_evidence_of(&tx)?.0 } else { spend_evidence_of(&tx)? });
    remember(key, e.clone());
    Some(e)
}

/// The tx door's own verdict, recorded: called by `Node::admit_tx_shared` for a send whose spend arm, member leg and
/// cover arm that door has just verified (the gossip arm runs all three on the transaction). Nothing is verified here;
/// a caller that did not run the three proofs must not call this.
pub fn record_verified_by_the_tx_door(tx: &PqTx) {
    if is_tree_form(tx) {
        return; // a tree-form body's evidence is never a tx door's: it is judged with its block's root
    }
    let (Some(e), Ok(body)) = (evidence_fields(tx), postcard::to_allocvec(tx)) else { return };
    remember(body_key(&body), Arc::new(e));
}

/// Every evidenced send among a block's carried bodies, in carried order (a body that proves nothing contributes
/// nothing: the row it was meant for then has no evidence, and the door refuses the block).
#[must_use]
pub fn block_evidence(block: &Block) -> Vec<Arc<SpendEvidence>> {
    block.tx_bodies.iter().filter_map(|b| evidence_of_body(b)).collect()
}

/// Every cell a block's CARRIED OBJECTS justify on its ledger: each credit-set and bond-set object's carried note cms
/// and own nullifiers. The pure form of `Node::object_own_cells_of`, read under the block's own key (a block at the
/// door carries it); a set that does not open or fails the carriage rule contributes nothing (fail-closed).
#[must_use]
pub fn object_own_cells(block: &Block) -> HashSet<[u8; 32]> {
    let mut cells = HashSet::new();
    let mut take = |blob: &[u8]| {
        cells.extend(crate::chain_object::carriage_note_refs(blob).into_iter().flatten().map(|(cm, _)| cm));
        cells.extend(crate::chain_object::object_own_nullifiers(blob).into_iter().flatten());
    };
    if let Some(key) = crate::block::credit_seal_key(&block.header, block.cover_key.as_ref()) {
        if crate::consensus::credit_set_is_carried_with_its_subjects(block, Some(&key), false).is_ok() {
            for blob in crate::block::credit_set_iter(&block.credit_set, Some(&key), &block.wide_objects).into_iter().flatten() {
                take(&blob);
            }
        }
    }
    for tx in crate::node::Node::bond_set_entries(&block.bond_set).0.into_iter().flatten() {
        take(&tx.blob);
    }
    cells
}

/// One ledger row as the door reads it.
#[derive(Clone, Copy)]
pub struct Row {
    pub tuple: SpendTuple,
    pub filing_d: Digest4,
    /// The row's published JUSTIFIED flags, in cell order `out0, out1, tag0, tag1` (`slot_ledger::PUB_FLAGS` lanes
    /// `j0, j1, t0, t1`, nonzero = justified). A justified cell is not the ledger's to admit: the ledger door leaves it
    /// out of its allow-list (`note_transition::verify_ledger_on_wire_with`) and the object that justifies it admits it,
    /// or nothing does. So it states no spend and asks for no evidence here.
    pub justified: [bool; 4],
}

/// The rows of a published ledger list.
#[must_use]
pub fn ledger_rows(published: &[usdm_decider::settlement_delta::LedgerPublished]) -> Vec<Row> {
    use usdm_decider::slot_ledger::{PUB_D, PUB_FLAGS, PUB_LC, PUB_OUT0, PUB_OUT1, PUB_TAG0, PUB_TAG1};
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    published
        .iter()
        .map(|p| Row {
            tuple: SpendTuple { out0_cm: b(p[PUB_OUT0]), out1_cm: b(p[PUB_OUT1]), nullifier: b(p[PUB_TAG0]), leaf_commit: b(p[PUB_LC]), tag1: b(p[PUB_TAG1]) },
            filing_d: p[PUB_D],
            justified: core::array::from_fn(|k| p[PUB_FLAGS][k] != 0),
        })
        .collect()
}

/// The cells of `rows` that the LEDGER ITSELF admits and that are not the block's own cover or its objects': the cells
/// that state a spend. One predicate for the door and the fold. Returns, per row, which of `out0, out1, tag0, tag1` do.
#[must_use]
pub fn spend_stated_cells(r: &Row, decoys: &HashSet<[u8; 32]>, cover_notes: &HashSet<[u8; 32]>, objects: &HashSet<[u8; 32]>) -> [bool; 4] {
    let t = &r.tuple;
    let note = |c: &[u8; 32], j: bool| !(j || cover_notes.contains(c) || objects.contains(c));
    let tag = |c: &[u8; 32], j: bool| !(j || decoys.contains(c) || objects.contains(c));
    [note(&t.out0_cm, r.justified[0]), note(&t.out1_cm, r.justified[1]), tag(&t.nullifier, r.justified[2]), tag(&t.tag1, r.justified[3])]
}

/// THE ROW RULE. `decoys` / `cover_notes` are the block's own cover cells and `objects` its carried objects' cells; a
/// cell in neither is SPEND-STATED. Returns the evidence each spend head matched (in row order), or the reason a row
/// states a spend nothing here proves.
///
/// * a row with a spend-stated OUTPUT is a spend's head: one evidence's exact tuple (both outputs, nullifier, leaf
///   commitment, claim tag), its filing digest, and its clock at or before the ledger's;
/// * every other spend-stated TAG belongs to a transaction whose head row this block states (a spend's remaining
///   constant-width tags ride on rows whose outputs are cover).
/// "Spend-stated" is exactly "admitted by the ledger itself and not the block's own cover or its objects'"
/// ([`spend_stated_cells`]): the rule covers every cell the ledger door's allow-list would admit, and no other.
pub fn rows_evidenced<'a>(
    rows: &[Row],
    decoys: &HashSet<[u8; 32]>,
    cover_notes: &HashSet<[u8; 32]>,
    objects: &HashSet<[u8; 32]>,
    evidence: &'a [Arc<SpendEvidence>],
    ledger_clock_ms: u64,
) -> Result<Vec<&'a SpendEvidence>, &'static str> {
    let mut heads: Vec<&SpendEvidence> = Vec::new();
    let mut loose_tags: Vec<[u8; 32]> = Vec::new();
    for r in rows {
        let t = &r.tuple;
        let stated = spend_stated_cells(r, decoys, cover_notes, objects);
        if !stated[0] && !stated[1] {
            // no spend-stated output: its tags are cover, an object's, justified by another object, or a stated spend's tail
            loose_tags.extend([(t.nullifier, stated[2]), (t.tag1, stated[3])].into_iter().filter(|(_, s)| *s).map(|(c, _)| c));
            continue;
        }
        // a spend's head: every cell of it is the ledger's own (a head with a justified cell is no transaction's row)
        if r.justified.iter().any(|j| *j) {
            return Err("a row states a spend's output beside a cell another object justifies");
        }
        let Some(e) = evidence.iter().map(Arc::as_ref).find(|e| e.tuple == *t) else {
            return Err("a row states a spend no carried transaction proves");
        };
        if e.filing_d != r.filing_d {
            return Err("a spend row's filing digest is not its transaction's");
        }
        if e.clock_ms > ledger_clock_ms {
            return Err("a spend row's transaction was proven under a clock past the ledger's");
        }
        if heads.iter().any(|h| h.tx_id == e.tx_id) {
            return Err("one transaction stated as two spend rows");
        }
        heads.push(e);
    }
    let of_heads: HashSet<[u8; 32]> = heads.iter().flat_map(|e| e.tags.iter().copied()).collect();
    if loose_tags.iter().any(|c| !of_heads.contains(c)) {
        return Err("a tag no stated spend of this block carries");
    }
    // ⭐ THE OTHER DIRECTION (spec LEVEL-AGGREGATE §15.5, speed5 2026-11-16): every tag of every stated spend IS stated — its
    // head row's two and its tail rows' (`settlement_delta::plan_ledger_rows_with_tails` lays `tags[2p], tags[2p+1]` for
    // every p). Until now only the tag ledger's chain (in circuit) made a spend's tag set complete; read natively here it no
    // longer rests on that proof alone, which is what lets a block in tree form carry a ledger without the bound step. A row
    // plan that leaves one of a spend's tags out would let that tag (a real nullifier among the decoys) stay unspent: refused.
    // §9.6: (3) value — a spend's every nullifier enters the set; (5) work — one set over ≤ the block's tag cells.
    // AI RESISTANT: (b) code, over the carried transactions every node verified itself. cons: none for an honest block.
    let stated: HashSet<[u8; 32]> =
        heads.iter().flat_map(|e| [e.tuple.nullifier, e.tuple.tag1]).chain(loose_tags.iter().copied()).collect();
    if heads.iter().any(|e| e.tags.iter().any(|t| !stated.contains(t))) {
        return Err("a stated spend's tag no row of this block states");
    }
    Ok(heads)
}

/// THE BLOCK DOOR'S QUESTION (`Node::preverify_block`, after the block's own proofs verified): is every spend this
/// block states the statement of a transaction it carries and this node verified? A ledger block is judged with its body
/// and cover key in hand, as the envelope delivers them; one that arrives without them cannot be judged and is refused
/// as a copy (the block's id is not condemned: a whole copy is judged afresh).
pub fn block_spends_are_evidenced(block: &Block) -> Result<(), &'static str> {
    let Some(nt) = block.note_transition.as_ref() else {
        return Ok(()); // no transition: the graft admits no spend's notes or tags at all
    };
    // The carried transactions are the ones this block's id commits (`NoteTransition::bodies`): every node that holds
    // the block then holds the same transactions, so what each decides from them here and at the fold is one verdict.
    if nt.bodies != crate::block::carried_commit(block.cover_key.as_ref(), &block.tx_bodies, &block.agg_tables) {
        return Err("the transactions beside this copy are not the ones the block commits");
    }
    // ⭐ lane agg — THE TREE-FORM BODIES' ROOT (`crate::agg_root`): a tree-form body carries no carrier at all; the
    // block's ONE root must prove every such body's statement, in carried order, or no row of this block is evidenced.
    // A block that carries no tree-form body carries no root (one encoding of "this block aggregates"; a body in any
    // other form is a full body and meets the full verify).
    let mut statements = Vec::new();
    for body in &block.tx_bodies {
        let Some(tx) = crate::chain_object::decode_exact::<PqTx>(body) else { continue };
        if is_tree_form(&tx) {
            // a tree-form body whose fields state nothing is refused whole: a root cannot be judged over a hole
            let (_, st) = tree_evidence_of(&tx).ok_or("a tree-form transaction whose fields are not one statement")?;
            statements.push(st);
        }
    }
    if statements.is_empty() {
        if !block.agg_tables.is_empty() {
            return Err("a block with no tree-form transaction carries a root");
        }
    } else {
        // §14 THE BUNDLE RELAY: one root a bundle, the bundles' bodies contiguous in carried order, the roots in that order
        // (`agg_root::verify_roots`); one root is the case the one-root door was
        if !crate::agg_root::verify_roots(&statements, &block.agg_tables) {
            return Err("the block's roots do not prove its tree-form transactions' statements, run by run in carried order");
        }
    }
    let evidence = block_evidence(block);
    if Some(nt.shape) != crate::note_transition::ledger_shape_wire() {
        // the legacy list: one tuple per stated spend, nothing hidden
        let spends = crate::note_transition::spend_tuples(nt).ok_or("a transition whose tuple list does not decode")?;
        return spends
            .iter()
            .all(|s| evidence.iter().any(|e| e.tuple == *s))
            .then_some(())
            .ok_or("a stated spend no carried transaction proves");
    }
    let published = crate::note_transition::decode_ledger_published(&nt.tuples).ok_or("a ledger whose list does not decode")?;
    let key = block.cover_key.ok_or("a ledger block without its cover key cannot be judged")?;
    if block.output_notes.is_empty() {
        return Err("a ledger block without its body cannot be judged");
    }
    let slots = crate::note_transition::header_note_cms_of_bodies(&block.output_notes, &key).ok_or("a body no slots derive from")?;
    if !crate::note_transition::ledger_outs_are_the_header_slots(&published, &slots) {
        return Err("the ledger's note cells are not the slots this body and key derive");
    }
    let (decoys, cover_notes) = crate::note_transition::ledger_cover_cells(&block.output_notes, &key);
    let objects = object_own_cells(block);
    rows_evidenced(&ledger_rows(&published), &decoys, &cover_notes, &objects, &evidence, nt.clock_ms).map(|_| ())
}

/// The anchors a held block's stated spends were proven under, by the head row each belongs to: what the fold judges
/// against the chain's ring. `None` when the block's rows are not evidenced here (a block that entered by a by-work door
/// and carries no bodies): the fold then has no native anchor to judge and says so.
#[must_use]
pub fn stated_spend_anchors(
    block: &Block,
    rows: &[Row],
    decoys: &HashSet<[u8; 32]>,
    cover_notes: &HashSet<[u8; 32]>,
    objects: &HashSet<[u8; 32]>,
    ledger_clock_ms: u64,
) -> Option<Vec<(SpendTuple, Digest4, Vec<[u8; 32]>)>> {
    let evidence = block_evidence(block);
    let heads = rows_evidenced(rows, decoys, cover_notes, objects, &evidence, ledger_clock_ms).ok()?;
    Some(heads.into_iter().map(|e| (e.tuple, e.anchor, e.tags.clone())).collect())
}
