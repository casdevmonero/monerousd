//! WHIR polynomial commitment scheme: commit, prove, and verify.

mod adapter;
pub mod committer;
pub mod hiding;
pub mod proof;
pub mod prover;
pub mod utils;
pub mod verifier;

pub use adapter::*;
pub use hiding::{HidingWhirProver, hvzk_prefix_prover, hvzk_verifier, prove_hvzk, verify_hvzk};

#[cfg(test)]
mod tests;
