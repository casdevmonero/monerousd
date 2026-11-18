//! Protocol configuration for WHIR polynomial commitments.

use alloc::vec::Vec;
use core::fmt::Display;

mod folding;
pub mod soundness;
pub mod whir;

pub use folding::{FoldingFactor, FoldingFactorError};
pub use soundness::SecurityAssumption;
pub use whir::{RoundConfig, WhirConfig};

/// Fallback proof-of-work difficulty when the user does not specify one.
///
/// 16 bits strikes a balance between prover cost and verifier DoS resistance.
/// - Higher values slow down the prover;
/// - Lower values weaken the PoW contribution to soundness.
pub const DEFAULT_MAX_POW: usize = 16;

/// Configuration parameters for WHIR proofs.
#[derive(Clone, Debug)]
pub struct ProtocolParameters {
    /// Initial logarithmic inverse rate for the first committed codeword.
    pub starting_log_inv_rate: usize,
    /// Log-inverse rates for the codewords committed after each intermediate
    /// WHIR round.
    pub round_log_inv_rates: Vec<usize>,
    /// The folding factor strategy.
    pub folding_factor: FoldingFactor,
    /// The type of soundness guarantee.
    pub soundness_type: SecurityAssumption,
    /// The security level in bits.
    pub security_level: usize,
    /// The number of bits required for proof-of-work (PoW).
    pub pow_bits: usize,
    /// HVZK-WHIR hiding gate (MonerousD original, task #135). When `true`, the commit path uses the
    /// salted `MerkleTreeHidingMmcs`, which hides the Merkle QUERY openings (proven green:
    /// `pcs::tests::whir_pcs_commits_and_verifies_under_hiding_mmcs`). This is PARTIAL hiding only —
    /// the out-of-domain answers + sumcheck round images are STILL published in the clear. The
    /// code-switch blinding that would close that leak (`crate::hvzk`, eprint 2026/391) is BUILT +
    /// unit-proven but NOT yet wired into the prover/verifier, so `hiding: true` alone is not full
    /// zero-knowledge. See `is_zk()` for the honest FULL-ZK gate. Base WHIR (`false`) publishes plain
    /// message-revealing evaluations and is not hiding at all.
    pub hiding: bool,
}

impl ProtocolParameters {
    /// `true` iff the WHIR proof is FULL zero-knowledge — the Four-Pillars Pillar-1 gate. STRICTER
    /// than `hiding`: full ZK needs BOTH the salted-MMCS query-hiding (`hiding`) AND the HVZK-WHIR
    /// out-of-domain-answer + sumcheck-round code-switch blinding (`crate::hvzk`). That OOD blinding
    /// is built + unit-proven but NOT yet wired into the prover/verifier, so this gate FAILS CLOSED —
    /// it never over-claims a privacy the published proof does not have (Pillar-1: never silently
    /// ship a weakened pillar). Flip `HVZK_OOD_BLINDING_WIRED` in the SAME commit that wires the
    /// `crate::hvzk` blinding into the prover/verifier (task #135's remaining soundness-critical step).
    pub fn is_zk(&self) -> bool {
        // Set true ONLY when crate::hvzk OOD-answer + sumcheck-round blinding is wired into BOTH the
        // prover and the verifier (not just the salted MMCS query-hiding). Until then is_zk() must
        // not claim full ZK — the OOD answers still leak the committed message.
        const HVZK_OOD_BLINDING_WIRED: bool = false;
        self.hiding && HVZK_OOD_BLINDING_WIRED
    }
}

impl Display for ProtocolParameters {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(
            f,
            "Targeting {}-bits of security with {}-bits of PoW - soundness: {:?}",
            self.security_level, self.pow_bits, self.soundness_type
        )?;
        writeln!(
            f,
            "Starting rate: 2^-{}, round_log_inv_rates: {:?}, folding_factor: {:?}",
            self.starting_log_inv_rate, self.round_log_inv_rates, self.folding_factor,
        )
    }
}
