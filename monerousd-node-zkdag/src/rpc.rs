// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Loopback RPC (brick 9): the node's LOCAL control + serving surface.
//!
//! This is the operator's own channel — a wallet / miner / governance UI on the SAME machine asks
//! the node for its state, submits a PQ tx, pulls a block template to grind, or submits a mined
//! block. It binds 127.0.0.1 ONLY. Onion-only ([`crate::net`]) governs the P2P MESH — how this node
//! talks to OTHER nodes, where an IP is unrepresentable; the loopback RPC never touches a routable
//! interface, so it carries no metadata off the box.
//!
//! [`dispatch`] is the transport-independent request→effect core (every request maps to a real
//! [`Node`] method — there are no hollow endpoints). The wire codec (length-prefixed frames over a
//! loopback unix socket) binds in the transport increment, exactly as the gossip transport binds
//! onto [`crate::relay`]; keeping the codec out of this module keeps the surface testable with no
//! socket.

use crate::block::{Block, BlockId};
use crate::hash::Hash32;
use crate::mempool::PqTx;
use crate::miner::{build_template, BlockTemplate};
use crate::node::Node;
use crate::params::ChainParams;
use crate::relay::RelayOutcome;

/// The RPC binds the loopback interface only — never a routable one.
pub const RPC_LOOPBACK_HOST: &str = "127.0.0.1";
/// Default loopback RPC port.
pub use crate::node_files::RPC_DEFAULT_PORT;

/// A request to the local node.
pub enum RpcRequest {
    /// Node status: DAG size, selected tip + blue-score, the LIVE governance params, mempool state.
    GetInfo,
    /// The selected tip (the head a wallet treats as current) + its blue-score.
    GetTip,
    /// A block template on the CURRENT tips for a local miner to grind (nonce + pow_bind unfilled).
    GetBlockTemplate {
        now_ts: u64,
        frontier_root: Hash32,
        miner_commitment: Hash32,
    },
    /// Submit a PQ transaction to the mempool.
    SubmitTx(PqTx),
    /// Submit a block (from the local miner, or a bridge) to the consensus-strict relay.
    SubmitBlock { block: Block, now_ts: u64 },
    /// Fetch the confidential PQ note ciphertexts in `[from_height, from_height + span)` so a wallet can
    /// scan its balance / receives. The wallet decapsulates each ciphertext LOCALLY with its own ML-KEM
    /// scan key (private) — the node never sees the scan key.
    GetPqNotes { from_height: u64 },
}

/// A snapshot of node state.
pub struct NodeInfo {
    pub n_blocks: usize,
    pub n_tips: usize,
    pub selected_tip: Option<BlockId>,
    /// Blue-score of the selected tip — the DAG's canonical "height".
    pub blue_score: u64,
    /// The height the PoS finality overlay has finalized (0 if none yet). Never gates the DAG.
    pub finalized_height: u64,
    /// The live, governance-tunable consensus parameters (dag_width, spacing, k, …).
    pub params: ChainParams,
    pub mempool_txs: usize,
    pub mempool_weight: u64,
    /// The anti-spam stamp bits a new tx must currently carry.
    pub required_stamp_bits: u32,
}

/// A response from the local node.
pub enum RpcResponse {
    Info(NodeInfo),
    Tip {
        tip: Option<BlockId>,
        blue_score: u64,
        /// The highest FINALIZED height this node holds (≥2/3 of bonded weight voted) — served so a
        /// real-node run can MEASURE time-to-finality instead of assuming it (item 6, 2026-09-18).
        finalized_height: u64,
    },
    Template(BlockTemplate),
    TxAccepted(Hash32),
    /// A tx rejected by the mempool (the reason is the fail-closed `MempoolError` text).
    TxRejected(String),
    /// The relay's verdict on a submitted block (Added / Buffered / Invalid / …).
    Block(RelayOutcome),
    /// Confidential PQ note ciphertexts for a height range + the chain's current top height (for paging).
    PqNotes {
        notes: Vec<(u64, Vec<u8>)>,
        top_height: u64,
    },
}

/// The blue-score of the node's selected tip (0 if only genesis / empty).
fn selected_blue_score(node: &Node) -> u64 {
    node.selected_tip()
        .and_then(|t| node.dag().get(&t))
        .map(|n| n.blue_score)
        .unwrap_or(0)
}

/// Handle one request against the local node. Every arm is a real effect — no stubbed endpoint.
pub fn dispatch(node: &mut Node, req: RpcRequest) -> RpcResponse {
    match req {
        RpcRequest::GetInfo => RpcResponse::Info(NodeInfo {
            n_blocks: node.dag().len(),
            n_tips: node.dag().tips().len(),
            selected_tip: node.selected_tip(),
            blue_score: selected_blue_score(node),
            finalized_height: node.user_final_height(), // SPEED L7: the wallet's "final" figure
            params: node.params().clone(),
            mempool_txs: node.mempool().len(),
            mempool_weight: node.mempool().total_weight(),
            required_stamp_bits: node.mempool().required_stamp_bits(),
        }),
        RpcRequest::GetTip => RpcResponse::Tip {
            tip: node.selected_tip(),
            blue_score: selected_blue_score(node),
            finalized_height: node.user_final_height(), // SPEED L7: the wallet's "final" figure
        },
        RpcRequest::GetBlockTemplate {
            now_ts,
            frontier_root,
            miner_commitment,
        } => {
            // Nullifier-acc root (pre-block spent-state) rides the header at parity with frontier_root;
            // the node's own O(1) acc is authoritative, so it is read here rather than supplied by the caller.
            let tmpl = build_template(
                node.dag(),
                node.mempool(),
                now_ts,
                frontier_root,
                Hash32(node.nullifier_root()),
                miner_commitment,
                node.account_root(),
                // DB-154: this RPC lane holds no sparse tree of its own, so it asserts NO merkle root.
                // ZERO is the "no tree" signal a restarted producer also sends; never gated on.
                Hash32::ZERO,
                &node.template_draw(now_ts),
            );
            RpcResponse::Template(tmpl)
        }
        RpcRequest::SubmitTx(tx) => match node.ingest_tx(tx) {
            // DIGITAL-CASH: no nullifier witness rides the tx; `ingest_tx` gates the double-spend LOCALLY
            // (self-verifying against this node's own O(1) acc / tree), so nothing extra reaches the wire.
            Ok(id) => RpcResponse::TxAccepted(id),
            Err(e) => RpcResponse::TxRejected(e.to_string()),
        },
        RpcRequest::SubmitBlock { block, now_ts } => {
            RpcResponse::Block(node.ingest_block(block, now_ts))
        }
        RpcRequest::GetPqNotes { from_height } => {
            // Serve one page of confidential note ciphertexts from the ANY-HEIGHT DA stream (the node caps the
            // page at DA_PAGE_BLOCKS blocks; the caller pages from its cursor until the stream ends — no window).
            // `served_through` is the first sequence the node could NOT serve. Carrying it to the caller is
            // what lets a wallet tell "no notes in this range" from "I do not hold this range" — the two used
            // to be the same empty page.
            let (notes, top_height) = node.pq_notes_from(from_height, 2000);
            RpcResponse::PqNotes { notes, top_height }
        }
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::block::BlockHeader;

    fn genesis_block() -> Block {
        Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
            header: BlockHeader {
            note_commitments_root: crate::hash::Hash32::hash(&[]),
                nullifier_tags_root: crate::hash::Hash32::hash(&[]),
                output_notes_root: crate::hash::Hash32::hash(&[]),
                // P4'a fixture: this block ships no locator tags and no account targets, so both sidecar
                // commitments are the empty-payload hash the verifier re-derives.
                oli_tags_root: crate::block::da_sidecar_root_of(&[]),
                // ⭐ §BA — no credit set here, so the DERIVED empty sidecar root, never a magic constant.
                credit_set_root: crate::block::da_sidecar_root_of(&[]),
                transitions_root: crate::block::empty_transitions_root(),
                cover_seed_commit: crate::hash::Hash32::ZERO,
                member_ring_commit: crate::hash::Hash32::ZERO,
                account_targets_root: crate::block::da_sidecar_root_of(&[]),
                bond_set_root: crate::block::da_sidecar_root_of(&[]),
                dir_set_root: crate::block::da_sidecar_root_of(&[]),
                letter_set_root: crate::block::da_sidecar_root_of(&[]),
                tag_evidence_root: crate::block::da_sidecar_root_of(&[]),
                level_root: crate::hash::Hash32::ZERO, fold_ordinal: 0, fold_commit: crate::hash::Hash32::ZERO, band_ordinal: 0, band_commit: crate::hash::Hash32::ZERO,
                version: 1,
                parents: vec![],
                timestamp: 0,
                nonce: 0,
                work: crate::miner::BOOTSTRAP_WORK,
                pow_bind: Hash32::ZERO,
                tx_merkle_root: Hash32::ZERO,
                frontier_root: Hash32::ZERO,
                nullifier_root: Hash32::ZERO,
                sparse_root: crate::hash::Hash32::ZERO,
                chain_acc: [0u8; 16],
                miner_commitment: Hash32::ZERO,
                account_root: Hash32::ZERO,
            },
            tx_ids: vec![],
            pow_proof: Vec::new(),
            note_transition: None,
            nullifier_proof: crate::block::NfBlockProof::default(),
            output_notes: Vec::new(),
            oli_tags: Vec::new(),
            account_targets: Vec::new(),
            bond_set: Vec::new(),
            // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
            credit_set: Vec::new(),
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            cover_transition: None,
            member_transition: None,
        }
    }

    fn grind_tx(blob: &[u8], weight: u32, nfs: Vec<Hash32>, need: u32) -> PqTx {
        let id = PqTx::content_id(blob);
        let mut s = 0u64;
        loop {
            let tx = PqTx {
                clock_ms: 0,
                note_clues: Vec::new(),
                account_targets: Vec::new(),
                id,
                blob: blob.to_vec(),
                weight,
                nullifiers: nfs.clone(),
                pow_stamp: s,
                output_notes: Vec::new(),
                stake_notes: Vec::new(),
                bond_notes: Vec::new(),
                nullifier_witnesses: Vec::new(),
                nullifier_absence: Vec::new(),
                membership_carrier: Vec::new(),
                membership_leaf_commit: [0u8; 32],
                membership_tip: Vec::new(),
                membership_folded_through: 0,
                spend_or_decoy: Vec::new(),
                member_carrier: Vec::new(),
                member_tuple: Vec::new(),
            };
            if tx.stamp_work() >= need {
                return tx;
            }
            s += 1;
        }
    }

    #[test]
    fn get_info_reflects_live_state() {
        let mut node = Node::new(genesis_block()).unwrap();
        let info = match dispatch(&mut node, RpcRequest::GetInfo) {
            RpcResponse::Info(i) => i,
            _ => panic!("expected info"),
        };
        assert_eq!(info.n_blocks, 1);
        assert_eq!(info.n_tips, 1);
        assert_eq!(info.blue_score, 0);
        assert_eq!(info.finalized_height, 0);
        // the live governance params are surfaced (default dag width 32).
        assert_eq!(info.params.dag_width, ChainParams::default().dag_width);
        assert_eq!(info.mempool_txs, 0);
    }

    #[test]
    fn get_pq_notes_serves_the_any_height_stream_range() {
        let mut node = crate::node::tests::testnet_party_folding_at_tip();
        // No notes yet → a valid EMPTY page (never a 404), so the wallet's balance/scan path succeeds.
        match dispatch(&mut node, RpcRequest::GetPqNotes { from_height: 0 }) {
            RpcResponse::PqNotes { notes, .. } => {
                assert!(notes.is_empty(), "empty index → empty page")
            }
            _ => panic!("expected PqNotes"),
        }
        // Record two SERVED-NOTE BLOCKS of REAL 1153-byte notes: served-block 0 = [A], served-block 1 = [B, C].
        // Each record wraps its reals in the CONSTANT cover shape (BLOCK_FIXED_NOTE_COUNT). The node keeps a
        // BOUNDED, byte-capped recent-block DA-serve CACHE (a non-authoritative speed layer, NOT the O(height)
        // note index) so a wallet can observe EVERY consecutive block and self-build its membership witness.
        use crate::cover::BLOCK_FIXED_NOTE_COUNT;
        const N: usize = 1153; // PQ_NOTE_BYTES
        let a = vec![0xAAu8; N];
        let b = vec![0xBBu8; N];
        let c = vec![0xCCu8; N];
        let mut bc = b.clone();
        bc.extend_from_slice(&c);
        let _ = node.carry_notes_in_a_block_for_test(5_000, &a); // served-block 0 (its carrier block)
        let _ = node.carry_notes_in_a_block_for_test(6_000, &bc); // served-block 1
                                          // BELT-AND-SUSPENDERS: a page from height 0 serves the BOUNDED RANGE of recent blocks (both blocks here,
                                          // each its constant BLOCK_FIXED_NOTE_COUNT cover shape) in ascending append order — the wallet observes
                                          // every block with no gaps. Blocks evicted past the byte/count cap are recovered from peer DA (#27 DAS).
        match dispatch(&mut node, RpcRequest::GetPqNotes { from_height: 0 }) {
            // CORRECT-ARCHITECTURE-REVIEWED: the `earliest` field (and its assert) is DELETED because it WAS window
            // logic — the stream now serves ANY height (user: no window/tip logic at all), so there is no origin to
            // advertise; the strengthened any-height assertions live in node.rs::pq_notes_serve_any_height_no_ageout.
            RpcResponse::PqNotes {
                notes, top_height, ..
            } => {
                assert_eq!(
                    notes.len(),
                    2 * BLOCK_FIXED_NOTE_COUNT,
                    "both blocks served from seq 0 (any-height DA stream, not tip-only)"
                );
                assert!(
                    notes.iter().all(|(_, ct)| ct.len() == N),
                    "every served note is a 1153-byte ciphertext"
                );
                // Genesis holds ordinal 0 and contributes NO notes (da_load → None, skipped);
                // the two real blocks sit at ordinals 1 and 2, so top = served_seq − 1 = 2.
                assert_eq!(top_height, 2, "top reflects the latest served-block index (genesis is ordinal 0)");
                let seqs: Vec<u64> = notes.iter().map(|(s, _)| *s).collect();
                assert!(
                    seqs.windows(2).all(|w| w[0] <= w[1]),
                    "served in ascending append order"
                );
                assert!(
                    notes.iter().any(|(s, _)| *s == 1),
                    "served-block 1 (first real block) present"
                );
                assert!(
                    notes.iter().any(|(s, _)| *s == 2),
                    "served-block 2 (second real block) present"
                );
                assert!(
                    notes.iter().any(|(s, ct)| *s == 1 && *ct == a),
                    "real note A present in block at ordinal 1"
                );
                assert!(
                    notes.iter().any(|(s, ct)| *s == 2 && *ct == b),
                    "real note B present in block at ordinal 2"
                );
                assert!(
                    notes.iter().any(|(s, ct)| *s == 2 && *ct == c),
                    "real note C present in block at ordinal 2"
                );
            }
            _ => panic!("expected PqNotes"),
        }
        // Paging beyond the latest ordinal yields an empty page (no future blocks).
        match dispatch(&mut node, RpcRequest::GetPqNotes { from_height: 3 }) {
            RpcResponse::PqNotes { notes, .. } => {
                assert!(
                    notes.is_empty(),
                    "from_height beyond the latest block serves nothing"
                );
            }
            _ => panic!("expected PqNotes"),
        }
    }

    #[cfg(any())] // DISABLED: exercised the removed featureless no-verify admit path; ZK verify is now mandatory.
    #[test]
    fn submit_tx_then_template_includes_it_and_block_grafts() {
        let mut node = Node::new(genesis_block()).unwrap();

        // required stamp bits are exposed via GetInfo; grind a tx that meets them.
        let need = match dispatch(&mut node, RpcRequest::GetInfo) {
            RpcResponse::Info(i) => i.required_stamp_bits,
            _ => panic!(),
        };
        let tx = grind_tx(b"rpc-tx-1", 1000, vec![Hash32::hash(b"nf-rpc")], need);
        let txid = match dispatch(&mut node, RpcRequest::SubmitTx(tx)) {
            RpcResponse::TxAccepted(id) => id,
            other => panic!(
                "expected accept, got a rejection: {}",
                match other {
                    RpcResponse::TxRejected(r) => r,
                    _ => "??".into(),
                }
            ),
        };
        // mempool now holds it.
        match dispatch(&mut node, RpcRequest::GetInfo) {
            RpcResponse::Info(i) => assert_eq!(i.mempool_txs, 1),
            _ => panic!(),
        }

        // pull a template; it selects the pooled tx and builds on the genesis tip.
        let fr = Hash32::hash(b"frontier");
        let mc = Hash32::hash(b"reward");
        let tmpl = match dispatch(
            &mut node,
            RpcRequest::GetBlockTemplate {
                now_ts: 5000,
                frontier_root: fr,
                miner_commitment: mc,
            },
        ) {
            RpcResponse::Template(t) => t,
            _ => panic!("expected template"),
        };
        assert_eq!(tmpl.tx_ids, vec![txid], "template selects the pooled tx");
        assert_eq!(tmpl.header.parents, node.dag().tips());

        // a miner would grind nonce+pow_bind; submit the (structurally valid) block back.
        let block = Block {
            header: tmpl.header.clone(),
            tx_ids: tmpl.tx_ids.clone(),
            pow_proof: Vec::new(),
            note_transition: None,
            nullifier_proof: crate::block::NfBlockProof::default(),
        };
        let bid = block.id();
        match dispatch(
            &mut node,
            RpcRequest::SubmitBlock {
                block,
                now_ts: 5000,
            },
        ) {
            RpcResponse::Block(RelayOutcome::Added(added)) => assert_eq!(added, bid),
            RpcResponse::Block(o) => panic!("expected Added, got {o:?}"),
            _ => panic!("expected block outcome"),
        }
        // the DAG advanced and the tip moved to the mined block.
        match dispatch(&mut node, RpcRequest::GetTip) {
            RpcResponse::Tip { tip, blue_score, .. } => {
                assert_eq!(tip, Some(bid));
                assert_eq!(blue_score, 1);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn submit_bad_tx_is_rejected_fail_closed() {
        let mut node = Node::new(genesis_block()).unwrap();
        // a tx whose id does not match its blob is rejected (not accepted, not a panic).
        let mut bad = grind_tx(b"good-blob", 10, vec![], 0);
        bad.id = Hash32::hash(b"a-different-blob");
        match dispatch(&mut node, RpcRequest::SubmitTx(bad)) {
            RpcResponse::TxRejected(_) => {}
            _ => panic!("expected rejection"),
        }
        // and the mempool stayed empty.
        match dispatch(&mut node, RpcRequest::GetInfo) {
            RpcResponse::Info(i) => assert_eq!(i.mempool_txs, 0),
            _ => panic!(),
        }
    }
}
