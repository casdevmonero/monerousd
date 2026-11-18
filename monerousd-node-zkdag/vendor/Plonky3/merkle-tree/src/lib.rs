#![no_std]

extern crate alloc;

pub mod accel;
mod hiding_mmcs;
mod merkle_tree;
mod mmcs;
mod pruning;

pub use hiding_mmcs::*;
pub use merkle_tree::MerkleTree;
pub use mmcs::{MerkleTreeError, MerkleTreeMmcs, PrunedBatchOpening};
pub use p3_symmetric::MerkleCap;
pub use pruning::{PrunedMerklePaths, PrunedPath};
