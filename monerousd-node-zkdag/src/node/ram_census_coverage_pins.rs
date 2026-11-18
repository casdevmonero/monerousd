// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::ram_census_coverage_pins` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use super::*;

/// ⭐⭐⭐ THE RESIDENT-SET CENSUS MUST COVER THE STORES THAT ACTUALLY HOLD THE BYTES.
///
/// ⛔⛔⛔ WHY THIS PIN EXISTS. `da_entry_census_named` listed the `da_*` maps and
/// `unspent_path_nodes` and nothing else, so its totals came to ~5 MB while a live PRODUCING node
/// held 300-490 MB resident. MEASURED 2026-09-16 on a node with an isolated HOME and ZERO dials:
/// tracked state grew ~11 KB/block while the resident set grew ~136 KB/block — about 92% of the
/// growth outside every store the node could name. A pillar ("phone-class RAM at any DAG width")
/// guarded by a census that covers 3% of the resident set is a pillar nobody is checking, and the
/// two attributions I made from READING the source — the 256-note cover, then the failed-dial Tor
/// churn — were both refuted by measurement afterwards.
///
/// ⭐ WHAT IT ASSERTS, and why a name check is the right shape here: the census is a LIST, and the
/// failure mode is a store being absent from it. Naming the two stores that were missing makes their
/// removal a test failure rather than a silent regression of coverage. The byte columns are asserted
/// to be REAL sums (non-zero once the stores hold anything), so a coverage entry that reports a
/// constant zero — which would restore the blind spot while passing a name check — is caught too.
#[test]
fn the_ram_census_covers_the_dag_and_the_mempool_not_only_the_da_maps() {
    let node = Node::new(tests::genesis_block()).expect("node boots");
    let rows = node.ram_census_named();
    let names: Vec<&str> = rows.iter().map(|(n, _, _)| *n).collect();
    for want in ["dag_blocks", "mempool_txs"] {
        assert!(
            names.contains(&want),
            "⛔⛔⛔ THE CENSUS LOST COVERAGE OF `{want}`. A store outside this list is a growth axis \
             nobody can attribute: that blind spot is exactly why a 300-490 MB resident set sat \
             against a ~5 MB census. Present names: {names:?}"
        );
    }
    // The DAG holds at least genesis, so its byte column must be a REAL sum, not a constant zero.
    let dag = rows
        .iter()
        .find(|(n, _, _)| *n == "dag_blocks")
        .expect("named above");
    assert!(
        dag.1 >= 1 && dag.2 > 0,
        "⛔ `dag_blocks` reports {} entries / {} bytes with genesis held — a coverage row that \
         always answers zero restores the blind spot while passing a name check",
        dag.1,
        dag.2
    );
    // Sorted largest-first, so the biggest store is the first thing a reader sees.
    for w in rows.windows(2) {
        assert!(
            w[0].2 >= w[1].2,
            "the census must be sorted by bytes, largest first — attribution starts with the \
             largest store, and an unsorted list buries it"
        );
    }
}





/// ⭐⭐⭐ WHICH SPARSE PROVER CAN RIDE A 500 ms BLOCK? ALL THREE, PROVE **AND** VERIFY, IN RELEASE.
///
/// ⛔ I CONCLUDED FROM A BAD MEASUREMENT ONCE ALREADY. The first cost pin timed
/// the (since deleted) compact sparse carrier in a DEBUG build, reported "23,274 ms — 46x the block
/// budget", and I removed the per-block proof on the strength of it. Release moved that to 15,264 ms:
/// the profile was worth only ~1.5x, so the number was never the point. The PROVER CHOICE was.
///
/// THE THREE ARE NOT INTERCHANGEABLE — they prove different statements, and the cheap one proves LESS:
///   * `..._fold_height1` binds the ENDPOINTS + the exact tag digest into the transcript. Its own doc:
///     *"the per-insert Merkle validity is NOT re-proven here"*. A node HOLDING the tree supplies the
///     rest with its own O(1) `verify_and_insert`; a TREELESS node cannot. Cheap because it proves less.
///   * `..._carrier` proves every insert in ONE monolithic N·DEPTH trace at block close (its compact
///     aggregate wrapper certified nothing and was deleted, 2026-10-26).
///   * `..._crosstie` proves the SAME per-insert statement, but as N INDEPENDENT tables chained by
///     cross-ties — its doc: *"a producer builds each AS ITS SPEND LANDS (streamed), so the only
///     block-close work is the batch fold, never a monolithic N·DEPTH prove"*.
///
/// ⭐ VERIFY IS THE NUMBER THAT DECIDES THIS, NOT PROVE. A producer can move proving off the critical
/// path; every ingesting node pays VERIFY on the apply path, once per block, against the 500 ms budget.
/// So both are timed here and the verify is what the wiring decision reads.
#[test]
fn every_sparse_prover_is_timed_prove_and_verify_against_the_block_budget() {
    use usdm_decider::nf_sparse_air as air;
    let n = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT;
    let mut tree = crate::nf_sparse::RefSparseNf::new();
    let pre_root = tree.root_bytes();
    let pre = crate::spend_frontier::cm_bytes_to_root(&pre_root).expect("a fresh root decodes");
    let padded: Vec<[u8; 32]> = (0..n as u64)
        .map(|i| {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&i.to_le_bytes());
            x[31] = 0xC0;
            x
        })
        .collect();
    let compact: Vec<usdm_decider::nf_compact_air::CompactInsertWitness> = padded
        .iter()
        .map(|nf| crate::nf_sparse::compact_insert_witness_for(nf, &tree.insert_and_witness(nf)).expect("a compact copath"))
        .collect();
    let inserts: Vec<air::SparseInsertWitness> = padded
        .iter()
        .map(|nf| crate::nf_sparse::insert_witness_for(nf, Vec::new()))
        .collect();

    // (1) THE MONOLITHIC CHAIN AIR.
    let t = std::time::Instant::now();
    let chain = crate::nf_sparse::prove_block_sparse_carrier(&compact, pre, n);
    let chain_ms = t.elapsed().as_millis();
    let (chain_bytes, post) = match &chain {
        Some((c, p)) => (c.len(), *p),
        None => (0, pre),
    };

    // (2) THE HEIGHT-1 FOLD — endpoints + tag digest only.
    let digest = air::sparse_fold_digest(&inserts, pre);
    let t = std::time::Instant::now();
    let fold = air::prove_sparse_fold_height1_bytes(&inserts, pre, post);
    let fold_ms = t.elapsed().as_millis();
    let t = std::time::Instant::now();
    let fold_ok = fold
        .as_ref()
        .is_some_and(|f| air::verify_sparse_fold_height1_bytes(f, pre, post, digest));
    let fold_v_ms = t.elapsed().as_millis();

    // (3) THE CROSS-TIE CARRIER — the full per-insert statement, streamable, treeless verify.
    // DB-453: the treeless path for the compact tree is the compact carrier itself, its keys bound to the tags
    let (ct_ms, ct_bytes) = (chain_ms, chain_bytes);
    let t = std::time::Instant::now();
    let ct_ok = chain.as_ref().is_some_and(|(c, _)| crate::nf_sparse::verify_block_sparse_carrier(c, pre, post, &padded));
    let ct_v_ms = t.elapsed().as_millis();
    let ct = chain.as_ref();
    let ct_post = post;

    eprintln!(
        "[sparse-prover-cost] n={n} budget=500ms | chain-AIR prove {chain_ms}ms {chain_bytes}B \
         | fold prove {fold_ms}ms verify {fold_v_ms}ms {}B ok={fold_ok} \
         | COMPACT (treeless) prove {ct_ms}ms VERIFY {ct_v_ms}ms {ct_bytes}B ok={ct_ok}",
        fold.as_ref().map(|f| f.len()).unwrap_or(0)
    );
    assert!(chain.is_some() && fold.is_some(), "the two known provers still build");
    // The cross-tie carrier is the treeless path; if it does not verify, it cannot be wired, and the
    // measurement must say so rather than being read as a green light.
    assert!(ct.is_some(), "the compact carrier builds at n={n}");
    assert!(ct_ok, "the compact carrier VERIFIES treeless against (pre, post, the block's tags)");
    assert_eq!(ct_post, post, "both full provers agree on the post-root");
}

