// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::adopted_node_gap_close_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
use crate::block::Block;
use crate::hash::Hash32;
use crate::node::{tests::genesis_block, Node};
use usdm_decider::nf_sparse_air::{nf_to_limbs, sparse_fold_digest_nfs, NfAbsenceBatchCarrier};

// ⛔ `cross_node_an_adopted_node_with_no_fold_inputs_still_admits_honest_and_rejects_spent` DELETED 2026-08-15 with the machinery it tested.
// It exercised the per-block fold-input store / stream serve, which is gone: those maps held one
// entry per block in RAM forever and nothing consumed their output. A test of a deleted growth
// store must go WITH it — keeping it would force the store back to keep the test green.
