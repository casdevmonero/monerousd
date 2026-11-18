// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! MonerousD's recursive proof tree (docs/LEVEL-AGGREGATE-SPEC-20261115.md §12): throughput that rises with the nodes,
//! because a block's proof stays constant while the payments it carries grow with the producers.
//!
//! * [`isa`]  the verifier row: column map, instruction set, native executor.
//! * [`vm`]   its constraint, its proof on the chained committed door, and the program claim.

pub mod door_ssa; // the SSA row: a carrier's committed / chained door as a program
pub mod fold_claims; // the SSA row: many program claims folded into one by a sumcheck in circuit
pub mod gate_eval;
pub mod gate_ssa; // the SSA row: an inner gate emitted as multiply-adds, folded at γ
pub mod gkr; // the SSA row (spec §13): the memory argument's fractional sum by GKR
pub mod isa;
pub mod ledger_ssa; // V2 (b): the block's joined ledger proof (a light-decider batch) verified on the builder
pub mod ssa; // the SSA row (spec §13): universal row-local gate, builder, packer, executor
pub mod ssa_inner; // a merge's child: an SSA proof verified inside an SSA program, its program claim deferred
pub mod ssa_door; // the SSA row's door: one commitment, the bus by GKR, the preprocessed program checked natively
pub mod tree_ssa; // the tree on the SSA row: leaves, merges, the root and its native check
pub mod verify_prog; // piece C (lane aggc): a committed-door proof's verification as a program for the verifier row
pub mod verify_whir_ssa; // the SSA row: WhirVerifier::verify on the builder (ported from verify_whir)
pub mod verify_whir; // piece C (lane aggc): WhirVerifier::verify as a program, its layers pinned against the native verifier
pub mod vm;

#[cfg(test)]
mod tests;
