// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! `node::idle_block_cover_fold_tests` moved VERBATIM out of node.rs (user 2026-10-27, lever 5); its path is unchanged.
//! GATE 31 root history (2026-09-03): n1's unspent root advanced every few blocks with NO wallet
//! activity; n2, NOT_READY since its jump, stayed at its adopted root for 100+ blocks. If every block's
//! FIXED cover payload folds into the unspent accumulator, a jumped node can only converge by folding
//! the cover of every block it skipped — derivable from the block's address alone — plus the real
//! payloads its headers commit to. This pins the property both parties must agree on.
use super::*;
use super::tests::genesis_block;

