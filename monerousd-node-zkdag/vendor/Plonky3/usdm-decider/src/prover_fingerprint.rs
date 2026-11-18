//! MonerousD Protocol — THE PROVER SOURCE FINGERPRINT (test support; lane-recursion, 2026-09-30).
//!
//! ⛔ WHY (lane-review K1, 03:50): a proof cache keyed on a VERIFIER-shape constant (`CERT_PROGRAM_DIGEST`) keeps
//! serving cached proofs across a prover regression — the cached bytes still verify, so the break is MASKED until
//! eviction. A cache hit must imply byte-identical prover code, so the key carries THIS digest.
//!
//! ⛔ AND IT NAMES THE SOURCES THE BINARY WAS COMPILED FROM (06:29, lane-db224-carriage): the first cut walked the tree
//! when the test process STARTED, so a binary built before a decider edit and run after it keyed its proofs under the
//! post-edit digest while proving with the pre-edit prover — the masking again, through the back door. The source part
//! is now computed by `build.rs` at BUILD time and compiled in (`USDM_PROVER_SOURCE_DIGEST`; cargo re-runs the script
//! on any change under `vendor/Plonky3`, the lockfile or the compiler). The one RUNTIME input that changes the prover's
//! behaviour, `MONEROUSD_PROVER_ASSERTS` (strict mode), is folded in here. ONE function for the node's certificate
//! cache and the decider's prove cache, so the two can never spell the key differently (§AO).
//!
//! Test support only: `#[cfg(any(test, feature = "test-support"))]`; no production binary carries it. `None` when the
//! build could not read the tree — a caller with no fingerprint has no cache, never a weaker key.

/// The compiled source digest (hex) — `none` when the build could not read the tree.
const SOURCE_DIGEST_HEX: &str = env!("USDM_PROVER_SOURCE_DIGEST");

fn source_digest() -> Option<[u8; 32]> {
    if SOURCE_DIGEST_HEX.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(SOURCE_DIGEST_HEX.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The prover fingerprint: blake3 over `"MUSD/prover-source/v2"`, the compiled source digest and the runtime
/// `MONEROUSD_PROVER_ASSERTS` value. `None` when the build had no source digest.
#[must_use]
pub fn prover_source_digest() -> Option<[u8; 32]> {
    static DIGEST: std::sync::OnceLock<Option<[u8; 32]>> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(|| {
        let src = source_digest()?;
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/prover-source/v2");
        h.update(&src);
        if let Some(v) = std::env::var_os("MONEROUSD_PROVER_ASSERTS") {
            h.update(v.to_string_lossy().as_bytes());
        }
        Some(*h.finalize().as_bytes())
    })
}

#[cfg(test)]
mod tests {
    /// The fingerprint exists on this build, is stable within a process, names the COMPILED sources (the build-time
    /// digest, not a walk of the tree the process sees now), and folds in the runtime strict-mode input.
    #[test]
    fn the_prover_fingerprint_is_the_compiled_sources_plus_the_runtime_mode() {
        let src = super::source_digest().expect("the build read the tree on a developer machine");
        let a = super::prover_source_digest().expect("a fingerprint");
        assert_eq!(a, super::prover_source_digest().expect("second read"), "one fingerprint per process");
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/prover-source/v2");
        h.update(&src);
        if let Some(v) = std::env::var_os("MONEROUSD_PROVER_ASSERTS") {
            h.update(v.to_string_lossy().as_bytes());
        }
        assert_eq!(*h.finalize().as_bytes(), a, "the fingerprint is the compiled source digest plus the runtime mode");
        assert_ne!(a, src, "the runtime layer is domain-separated from the source digest");
    }
}
