// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE WHOLE-CHAIN CERTIFICATE — the join door's certificate half.
//!
//! ## What an adopter is actually asking
//!
//! A joining node holds no chain; that is why it is jumping. It cannot re-derive the tip accumulator, so
//! the certificate itself must carry the anchoring: producing one must REQUIRE HOLDING THE CHAIN.
//!
//! ⛔ The shipped decider ([`crate::whole_chain`]) does not do that — it proves a FIXED public AIR whose
//! trace is a function of `WHOLE_CHAIN_T` alone, with the accumulator only SEEDING the transcript. So its
//! (prove, verify) pair attests exactly one fact, *"somebody ran the prover with THIS accumulator"*, and
//! every party can run the prover.
//!
//! ⛔ The first replacement (kill list §AJ) folded with its OWN commutative accumulator and left the inner
//! statement a prover-chosen witness the verifier never saw. ⛔ The second (`ivc_one_table`, 2026-09-1x) put
//! the step in ONE committed AIR table whose recursive verifier read W openings — no fixpoint: a step of the
//! certificate's own shape did not fit the certificate (spec § "the whole-chain certificate cannot be made
//! sound by composition", 2026-09-27). It is deleted at source.
//!
//! ## What it is now (DESIGN Z, spec `docs/O1-OPENINGS-RECURSION-SPEC.md` §M6)
//!
//! The certificate IS a chain of [`crate::certificate_door`] steps: each step is ONE Spartan-committed proof
//! of the release's universal-row R1CS running the verifier of the step below it (the whole inner verifier
//! as rows: two sumchecks, the matrix argument, two WHIR openings) followed by the acc-step rows that fold
//! this block's summary and work onto the inner state. So:
//!   * the ONLY way to begin is a step over the GENESIS proof (`prove_genesis_certificate`), which anchors at
//!     [`WHOLE_CHAIN_GENESIS_ACC`] with ZERO work (`IOCHK_BASE` admits exactly the release program or the
//!     genesis program as the inner program);
//!   * every claimed unit of work came from a step that verified its predecessor, and the inner state a step
//!     consumes is the inner proof's own public io (checked natively before proving and by the rows);
//!   * the accumulator recurrence is `compress(acc, summary)` — the production permutation, ONE definition
//!     (`acc_program::AccStep`), sequential, so it binds ORDER.
//!
//! What this module owns is [`chain_summary_digest`] — the single value a step folds per block, binding every
//! field an adopter installs from a tip — and the certificate's public statement `(acc, work, tip_summary,
//! tip_block_work)`, which the step's io block 3 names as `state_hash` of exactly those four values: the
//! adopter recomputes it and compares, never reads it off the wire.
//!
//! ## COST — MEASURED 2026-09-28 (fixpoint runs 5 and 6, T = 2^14)
//!
//! One step per block applied, each ONE proof of ONE fixed shape: 178,093 B every step (`certificate_door::
//! CERT_BYTES_MAX` = 393,216 bounds it, prover and verifier; the T = 2^15 JB step is 377,393 B, measured 2026-10-24); prove ≈ 5 min per step on the 10-core machine
//! (the phase profile is printed by the prover); VERIFY 217–221 ms, O(1) — no per-block data, nothing that
//! grows with height. A strided byte-flip census over a real step (2,920 flips) was refused at every byte.
//! The genesis proof is proven once per process (`genesis_step`) and only by a node that starts a certificate
//! from nothing; a joiner INHERITS the served certificate ([`WholeChainCert::inherit`]) and continues it — the
//! certificate is a chain object carried forward, not a per-node possession.
//!
//! ROOT-LAYER: the anchoring is constrained where the step HAPPENS, inside the rows a recursive verifier
//! re-proves — not re-checked by a reader afterwards (§AJ measured that a reader-side check does not survive
//! the level above it).
//!
//! MUST-STAY-GREEN: `certificate_door`'s fixpoint pin; the node's DSYNC adopt gate (`sync.rs`), which keeps its
//! three checks in the same order.

use crate::acc_program::{state_hash, AccStep, AccStepIn, GENESIS_SUMMARY};
use crate::certificate_door::{certificate_state, prove_certificate_step, prove_genesis_certificate, release_program_digest, verify_certificate_step, CertParams, CertStep, CERT_CARRIER, CERT_FIXED_CARRIER, CERT_PROGRAM_DIGEST, CERT_T_BITS};
use crate::nullifier_insert_air::{kred, poseidon_pair_native};
use crate::poseidon2_compress::{Digest, DIGEST_LANES};
use std::sync::OnceLock;

/// Domain separator for one block's whole-chain SUMMARY digest — the value folded per step.
pub const WHOLE_CHAIN_SUMMARY_DOMAIN: u64 = 0x5743_435f_5355_4d4d; // "WCC_SUMM"

/// The FIXED genesis chain accumulator every certificate anchors at — the empty fold, before any summary
/// is applied. Public constant: two honest nodes on one network start here by construction, and a party
/// with no chain must fold from HERE to its claimed tip, which it cannot do without each real block's
/// summary in turn. Matches [`crate::note_membership_air`]'s genesis convention (an all-zero digest), the
/// value `Node::MEMBERSHIP_GENESIS_ACC` also uses.
pub const WHOLE_CHAIN_GENESIS_ACC: Digest = [0u64; DIGEST_LANES];

/// The whole-chain SUMMARY digest for one block — the single value the certificate folds, a
/// domain-separated Poseidon compression of every field the adopter installs from a tip. Binding all of
/// them here is what makes the certificate a statement about the WHOLE adopted state: a forged root, a
/// lied blue-work, a swapped validator-set root or a wrong genesis each changes the summary, so it
/// changes the accumulator, so the fold from genesis no longer reaches the claimed tip.
///
/// The caller flattens each field to limbs; this compresses them pairwise (the tree's one-round
/// Poseidon `poseidon_pair_native`, the same primitive every fold in this crate uses) into one digest.
/// It is a function of the fixed field count — no chain-length term, no per-note or per-block growth.
#[allow(clippy::too_many_arguments)]
pub fn chain_summary_digest(
    tip_id: Digest,
    blue_score: u64,
    blue_work: u128,
    frontier_root: Digest,
    nullifier_root: Digest,
    sparse_root: Digest,
    nf_unspent_acc: Digest,
    letter_acc: Digest,
    dir_acc: Digest,
    validator_set_root: Digest,
    genesis_id: Digest,
) -> Digest {
    // Scalars enter as their own limb vector so no field is silently dropped: blue_score (u64) and
    // blue_work (u128, low/high) are placed in fixed limbs.
    let scalars = crate::poseidon2_compress::lanes_of(&[
        kred(WHOLE_CHAIN_SUMMARY_DOMAIN),
        blue_score,
        blue_work as u64,
        (blue_work >> 64) as u64,
    ]);
    let mut acc = poseidon_pair_native(scalars, tip_id);
    for field in [
        frontier_root,
        nullifier_root,
        sparse_root,
        nf_unspent_acc,
        letter_acc,
        dir_acc,
        validator_set_root,
        genesis_id,
    ] {
        acc = poseidon_pair_native(acc, field);
    }
    acc
}

// The anchor ring's digest is defined ONCE, in the node (`sync::anchor_ring_digest`, 2026-09-29 04:05): it rides the
// FRONTIER input of the chain summary (`blake3(frontier.root ‖ height ‖ anchor_ring_digest(ring))`), so the certificate
// binds every ring entry with no change to `chain_summary_digest` or `state_hash`. A decider-side twin was drafted and
// deleted the same hour — two spellings of one consensus digest is how sides drift.

/// The release's certificate parameters, built once per process from the release constants (seconds: the
/// template, its fixed columns and their commitment root, and the verifier program's digest from the proof SHAPE
/// alone — M6-D). The digest is also pinned as [`CERT_PROGRAM_DIGEST`], the value the fixpoint pin measured over
/// REAL proofs: a process whose shape-derived digest is not the pinned one has a certificate no release verifier
/// accepts, so it refuses to start rather than mint steps nobody verifies (fail closed, loud). A shape change is a
/// release act — it moves the constant on purpose, never silently.
#[must_use]
pub fn release_params() -> &'static CertParams {
    static PARAMS: OnceLock<CertParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        let p = CertParams::new(CERT_T_BITS, CERT_CARRIER, CERT_FIXED_CARRIER)
            .expect("the release's certificate shapes settle (a fixpoint of the fixed table's size)");
        let digest = release_program_digest(&p).expect("the release's verifier program fits T");
        assert_eq!(digest, CERT_PROGRAM_DIGEST, "the certificate's verifier program moved without a release bump: no certificate");
        p.with_program_digest(digest)
    })
}

/// The genesis proof — the base step's inner object — proven once per process, the first time a node starts
/// a certificate from nothing. `None` when the prover refuses (a node that cannot prove genesis cannot certify).
fn genesis_step() -> Option<&'static CertStep> {
    GENESIS.get_or_init(|| prove_genesis_certificate(release_params())).as_ref()
}

/// The process's one genesis proof (see [`genesis_step`]).
static GENESIS: OnceLock<Option<CertStep>> = OnceLock::new();

/// ⛔ TEST BUILDS ONLY (`cfg(test)` / the `test-support` feature the node's dev-dependency enables — never a node
/// binary): INSTALL a stored genesis proof, ONLY after `verify_genesis_certificate` re-verifies it against the release
/// parameters. No file I/O here — the node's approved cross-run cert cache (`sync::test_cert_fixture_cache`) reads the
/// bytes. MEASURED 2026-10-02: the genesis proof costs 399–475 s and EVERY test process that certifies a chain proved
/// it again (the step cache never sees it — it is the base step's inner object). `false` when it does not verify or a
/// genesis proof is already held.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn install_genesis_proof_for_test(bytes: Vec<u8>) -> bool {
    let p = release_params();
    let step = CertStep { bytes, io: crate::certificate_door::genesis_io(p) };
    if !crate::certificate_door::verify_genesis_certificate(p, &step) {
        return false;
    }
    GENESIS.set(Some(step)).is_ok()
}

/// ⛔ TEST BUILDS ONLY: the genesis proof's bytes this process ALREADY holds — never proves one — for the node's
/// cross-run cert cache to keep.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn genesis_proof_held_for_test() -> Option<Vec<u8>> {
    GENESIS.get().and_then(Option::as_ref).map(|g| g.bytes.clone())
}

/// ⭐ The incremental whole-chain CERTIFICATE — one per producing/serving node, advanced by ONE step as
/// each block is applied. Holds a constant-size running step (the recursion collapses history) and the four
/// public values it names, never per-block data.
#[derive(Clone)]
pub struct WholeChainCert {
    acc: Digest,
    work: u128,
    tip_summary: Digest,
    tip_block_work: u128,
    /// O1-FOOTPRINT-REVIEWED: bounded by `certificate_door::CERT_BYTES_MAX` — ONE `Option`, replaced in place
    /// as the chain advances, never a per-block map.
    running: Option<CertStep>,
}

impl WholeChainCert {
    #[must_use]
    pub fn new() -> Self {
        Self { acc: WHOLE_CHAIN_GENESIS_ACC, work: 0, tip_summary: GENESIS_SUMMARY, tip_block_work: 0, running: None }
    }

    /// The accumulator this certificate currently attests.
    #[must_use]
    pub fn acc(&self) -> Digest {
        self.acc
    }

    /// The PROVEN work this certificate currently attests — what fork choice reads.
    #[must_use]
    pub fn work(&self) -> u128 {
        self.work
    }

    /// Apply ONE block: fold its summary and its work, recursively verifying the step below. The first
    /// call is the BASE step over the genesis proof (anchored at [`WHOLE_CHAIN_GENESIS_ACC`] with zero work);
    /// every later call consumes this certificate's own previous step. Fail-closed — never advances on an
    /// unprovable step (a work sum leaving `u128`, an inner state that is not the inner's, rows that do not
    /// fit or do not satisfy, a proof past the cap).
    #[must_use]
    pub fn step(&mut self, summary: Digest, block_work: u128) -> bool {
        let input = AccStepIn {
            acc_prev: self.acc,
            work_prev: self.work,
            summary_prev: self.tip_summary,
            bw_prev: self.tip_block_work,
            summary,
            block_work,
        };
        let Some(native) = AccStep::compute(input) else {
            return false;
        };
        let stepped = if bound_mode() {
            bound_step(self.running.as_ref(), &native)
        } else {
            let params = release_params();
            match self.running.as_ref() {
                None => genesis_step().and_then(|g| prove_certificate_step(params, g, input)),
                Some(inner) => prove_certificate_step(params, inner, input),
            }
        };
        let Some(step) = stepped else {
            return false; // fail-closed: never advance the accumulator on an unprovable step
        };
        self.acc = native.acc;
        self.work = native.work;
        self.tip_summary = summary;
        self.tip_block_work = block_work;
        self.running = Some(step);
        true
    }

    /// The certificate and every PUBLIC value a remote adopter needs to check it. `None` before the first
    /// step — an empty chain has nothing to certify.
    #[must_use]
    pub fn finalize(&self) -> Option<WholeChainProof> {
        Some(WholeChainProof {
            step: self.running.clone()?,
            acc: self.acc,
            work: self.work,
            tip_summary: self.tip_summary,
            tip_block_work: self.tip_block_work,
        })
    }

    /// ⭐ CONTINUE a served certificate: a DSYNC joiner that adopted `p` carries the chain's certificate
    /// forward instead of starting one at genesis it could not fold to the tip anyway. Accepted only when `p`
    /// verifies (the step, and its io block 3 against the four public values); every later `step` then binds
    /// to those values through the inner-state check. Fail-closed: `None` for anything that does not verify.
    #[must_use]
    pub fn inherit(p: &WholeChainProof) -> Option<Self> {
        verify_whole_chain_cert(p).then(|| Self {
            acc: p.acc,
            work: p.work,
            tip_summary: p.tip_summary,
            tip_block_work: p.tip_block_work,
            running: Some(p.step.clone()),
        })
    }
}

impl Default for WholeChainCert {
    fn default() -> Self {
        Self::new()
    }
}

/// A finished certificate: the step plus the public statement it stands for. Every field is something
/// the adopter checks against its own expectations; none of it is trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WholeChainProof {
    /// O1-FOOTPRINT-REVIEWED: bounded by `certificate_door::CERT_BYTES_MAX` (prover and verifier refuse a
    /// step above it), constant at any chain height regardless of how many blocks it folded.
    pub step: CertStep,
    pub acc: Digest,
    pub work: u128,
    pub tip_summary: Digest,
    pub tip_block_work: u128,
}

/// THE O(1) WHOLE-CHAIN VERIFY (adopter side). ONE constant-size check at any height: the top step verifies
/// at the release's door (pad, program digest, fixed root, cap, the proof), and its io block 3 is the
/// `state_hash` of exactly the four public values — so that step could only exist if the step below it
/// did, down to a base step over the genesis proof with zero work.
///
/// The adopter compares `p.acc` and `p.work` with what the bundle claims and with its own fork choice; a
/// certificate that folds to any other tip, over any other summary, or claiming work no chain of steps
/// produced, is refused. Fail-closed.
#[must_use]
pub fn verify_whole_chain_cert(p: &WholeChainProof) -> bool {
    let step_ok = if bound_mode() { bound_verify(&p.step) } else { verify_certificate_step(release_params(), &p.step) };
    step_ok && certificate_state(&p.step) == Some(state_hash(&p.acc, p.work, &p.tip_summary, p.tip_block_work))
}

/// The bound step, or nothing: a node binary has no bound module, and `bound_mode()` is `false` there.
fn bound_step(inner: Option<&CertStep>, native: &AccStep) -> Option<CertStep> {
    #[cfg(any(test, feature = "test-support"))]
    {
        bound::step(inner, native)
    }
    #[cfg(not(any(test, feature = "test-support")))]
    {
        let _ = (inner, native);
        None
    }
}

/// The bound check, or a refusal: a node binary verifies real proofs only.
fn bound_verify(s: &CertStep) -> bool {
    #[cfg(any(test, feature = "test-support"))]
    {
        bound::verify(s)
    }
    #[cfg(not(any(test, feature = "test-support")))]
    {
        let _ = s;
        false
    }
}

/// Is this process running the BOUND certificate double (see [`bound`])? Always `false` in a node binary. Shared by every
/// bound double of the testing format (the asset-mint carrier's too, `whir_rec_block`), so a process is bound or proven
/// as a whole and the two forms never mix.
#[inline]
pub(crate) fn bound_mode() -> bool {
    #[cfg(all(feature = "test-support", not(test)))]
    {
        bound::active()
    }
    #[cfg(not(all(feature = "test-support", not(test))))]
    {
        false
    }
}

/// ⛔ TEST BUILDS ONLY: is this test process running bound certificates? The node's step cache stands aside when it
/// is (a bound step costs microseconds; there is nothing to cache).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn certs_are_bound() -> bool {
    bound_mode()
}

/// ⛔ TEST BUILDS ONLY: would the REAL certificate door accept this proof's step (whatever mode the process runs)? The
/// pin that a bound certificate can never pass for a real one reads it.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn real_door_accepts_for_test(p: &WholeChainProof) -> bool {
    verify_certificate_step(release_params(), &p.step)
}

/// ⭐⭐⭐ THE BOUND CERTIFICATE — the certificate PROVER's test double (user 2026-10-02: "make our test fast and accurate
/// … the test themselves have become the bug"; the testing format in memory `feedback_testing_format_20261002`).
///
/// MEASURED 2026-10-02: one whole-chain certificate step is a T = 2^14 recursive WHIR prove, 320–506 s (374 s at 8
/// threads — the opening phases dominate, threads barely help), and ~64 node test call sites build, serve or adopt a
/// sync bundle — every one of them re-proving whole chains after ANY decider edit (the cache key moves with the prover
/// source, correctly). Node-logic tests were paying hours for a proof whose soundness is not what they assert.
///
/// WHAT IT KEEPS: everything a node-logic test can observe. The bound step carries the SAME io layout — block 3 is
/// `state_hash(acc, work, tip_summary, tip_block_work)`, so [`verify_whole_chain_cert`] still binds every public value
/// (a moved acc, work or tip is REFUSED); block 1 is the inner's state, checked at step time exactly as the prover's
/// `inner.io[3] == state_prev` rule; and the bytes are a digest of the io, so a flipped byte is REFUSED.
/// WHAT IT DROPS: only the recursive WHIR proof — its soundness is the certificate door's own pins (the decider's
/// `cfg(test)`, which NEVER runs bound), the proven tier (`MONEROUSD_TEST_CERTS=proven`), and the real-node journeys.
/// WHERE IT CAN EXIST: test builds only (`test-support`, which only the node's dev-dependency enables) — a node binary
/// has no bound path at all. A bound step NEVER passes the real verifier (block 0 is the bound marker, not
/// `digest(P)`), and a process is bound or proven as a whole, so the two forms never mix.
#[cfg(any(test, feature = "test-support"))]
mod bound {
    use crate::acc_program::{genesis_state_hash, AccStep};
    use crate::certificate_door::CertStep;
    use crate::universal_row::{io_block, IO_LEN};
    use crate::hiding_decider::Fa4;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};

    /// `MONEROUSD_TEST_CERTS=proven` runs real certificates (the proven tier); anything else is bound.
    #[cfg(all(feature = "test-support", not(test)))]
    pub(super) fn active() -> bool {
        static ACTIVE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ACTIVE.get_or_init(|| std::env::var("MONEROUSD_TEST_CERTS").map_or(true, |v| v != "proven"))
    }

    /// io block 0 of a bound step — never a program digest, so the real door refuses it.
    fn marker() -> Vec<Fa4> {
        let n = io_block(0).len();
        (0..n).map(|i| Fa4::from_u64(0x0B0D_0000 + i as u64)).collect()
    }

    fn bytes_of(io: &[Fa4]) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/test-bound-cert/v1");
        for x in io {
            h.update(&x.as_canonical_u64().to_le_bytes());
        }
        h.finalize().as_bytes().to_vec()
    }

    /// One bound step over `inner` (or over genesis): refused when the inner is a real proof (no mixing) or its state
    /// is not this step's previous state — the same rule `prove_certificate_step` applies.
    pub(super) fn step(inner: Option<&CertStep>, native: &AccStep) -> Option<CertStep> {
        let prev: Vec<Fa4> = match inner {
            None => genesis_state_hash().to_vec(),
            Some(i) => {
                if !verify(i) {
                    return None;
                }
                i.io[io_block(3)].to_vec()
            }
        };
        if prev[..] != native.state_prev[..] {
            return None;
        }
        let mut io = vec![Fa4::ZERO; IO_LEN];
        io[io_block(0)].copy_from_slice(&marker());
        io[io_block(1)].copy_from_slice(&native.state_prev);
        io[io_block(3)].copy_from_slice(&native.state);
        Some(CertStep { bytes: bytes_of(&io), io })
    }

    /// A bound step's own check: its marker, and bytes that are the digest of its io.
    pub(super) fn verify(s: &CertStep) -> bool {
        s.io.len() == IO_LEN && s.io[io_block(0)] == marker()[..] && s.bytes == bytes_of(&s.io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate_door::{emit_certificate_program, first_unsatisfied_row};
    use crate::universal_row::io_block;

    /// A distinct summary per height. `i` is a chain HEIGHT index, not a cover / nullifier count — the
    /// per-block cover width (256) is not a parameter of this fold at all.
    fn summary(i: u64) -> Digest {
        summary_with(i, crate::poseidon2_compress::lanes_of(&[0, i, 0, 0]), crate::poseidon2_compress::lanes_of(&[0, 0, i, 0]))
    }
    /// `summary(i)` with the two nullifier roots chosen by the caller — the restart door's swapped-root pins.
    fn summary_with(i: u64, nullifier_root: Digest, sparse_root: Digest) -> Digest {
        chain_summary_digest(
            crate::poseidon2_compress::lanes_of(&[kred(0x9E37_79B9_7F4A_7C15), i]),
            i,
            (i as u128) * 7,
            crate::poseidon2_compress::lanes_of(&[i, 0, 0, 0]),
            nullifier_root,
            sparse_root,
            crate::poseidon2_compress::lanes_of(&[0, 0, 0, i]),
            crate::poseidon2_compress::lanes_of(&[0, i, i, 0]),
            crate::poseidon2_compress::lanes_of(&[0, 0, i, i]),
            crate::poseidon2_compress::lanes_of(&[i, 0, i, 0]),
            crate::poseidon2_compress::lanes_of(&[7, 7, 7, 7]),
        )
    }

    /// ⛔⛔⛔ THE PIN THAT WAS RED (§AJ) — DOES THE CERTIFICATE ANCHOR THE CHAIN, OR ONLY ASSERT ITS TOP STEP?
    /// (heavy: T = 2^14 steps, ~25 min). An honest 2-block chain certifies and verifies; a different second block
    /// reaches a different accumulator; a joiner INHERITS the served certificate and continues it with a third
    /// block that verifies; the attacker holding NO chain starts where anyone may (a real, verifying base step) and
    /// declares the rich state it wishes it had inherited — refused natively (the declared inner state is not the
    /// inner's), and refused by the ROWS when it also forges the inner io to match (the inner proof no longer
    /// verifies under the forged statement: the trace does not satisfy, the prover mints nothing).
    #[test]
    fn pin_the_certificate_must_anchor_the_chain_not_merely_assert_its_top_step() {
        let block_work = 1u128 << 30;
        let t0 = std::time::Instant::now();
        let mut cert = WholeChainCert::new();
        for s in [summary(0), summary(1)] {
            assert!(cert.step(s, block_work), "an honest step must fold");
        }
        let real = cert.finalize().expect("an honest certificate finalises");
        assert!(verify_whole_chain_cert(&real), "an honest certificate must verify at its own tip");
        assert_eq!(real.work, 2 * block_work, "two blocks of work, and no more");
        let t_two = t0.elapsed();
        // a chain that applied a DIFFERENT second block reaches a different accumulator (native: the fold is a
        // function of WHICH blocks, not how many)
        let other_acc = crate::poseidon2_compress::compress(&crate::poseidon2_compress::compress(&WHOLE_CHAIN_GENESIS_ACC, &summary(0)), &summary(2));
        assert_ne!(other_acc, real.acc, "two different histories must not share an accumulator");
        // the joiner: inherits the served certificate and continues it
        let mut joiner = WholeChainCert::inherit(&real).expect("a verifying certificate is inherited");
        assert_eq!((joiner.acc(), joiner.work()), (real.acc, real.work));
        assert!(joiner.step(summary(2), block_work), "the inherited certificate continues");
        let cont = joiner.finalize().expect("finalises");
        assert!(verify_whole_chain_cert(&cont), "the continued certificate verifies");
        assert_eq!(cont.work, 3 * block_work);
        let t_three = t0.elapsed();
        // ⛔ THE ATTACKER: holds no chain. It stands on the REAL base step (calibration: it verifies) and declares
        // an invented inheritance.
        let base = {
            let mut c = WholeChainCert::new();
            assert!(c.step(summary(0), block_work));
            c.finalize().unwrap()
        };
        assert!(verify_whole_chain_cert(&base), "CALIBRATION: the attacker's own base step verifies");
        let inv = AccStepIn { acc_prev: [0xDEAD_BEEFu64; DIGEST_LANES], work_prev: 1u128 << 120, summary_prev: summary(9_999_999), bw_prev: block_work, summary: summary(9_999_998), block_work };
        let p = release_params();
        assert!(prove_certificate_step(p, &base.step, inv).is_none(), "⛔ a step declaring an inheritance its inner does not have was minted (native check)");
        // …and when the attacker ALSO forges the inner io's state block to match its invention, the ROWS refuse:
        // the inner proof was made under its true statement, so the certificate's re-derived transcript diverges
        let mut forged_inner = base.step.clone();
        forged_inner.io[io_block(3)].copy_from_slice(&state_hash(&inv.acc_prev, inv.work_prev, &inv.summary_prev, inv.bw_prev));
        let native = AccStep::compute(inv).unwrap();
        let em = emit_certificate_program(p, &forged_inner, &native).expect("the rows emit for any inner of the shape");
        let refused_at = first_unsatisfied_row(p, &em);
        assert!(refused_at.is_some(), "⛔ the rows accepted an inner proof under a forged statement");
        assert!(prove_certificate_step(p, &forged_inner, inv).is_none(), "⛔ THE CERTIFICATE DOES NOT ANCHOR THE CHAIN: a party holding NO chain minted a certificate for an accumulator it invented");
        // the same bytes cannot be re-labelled either: the public values are bound by io block 3
        let relabelled = WholeChainProof { acc: other_acc, ..real.clone() };
        assert!(!verify_whole_chain_cert(&relabelled), "a certificate re-labelled with another accumulator verified");
        let more_work = WholeChainProof { work: real.work + 1, ..real.clone() };
        assert!(!verify_whole_chain_cert(&more_work), "a certificate re-labelled with more work verified");
        // ⭐ THE RESTART DOOR'S TWO ROOTS (Lane A, 2026-09-29): a node resuming from a persisted nullifier view checks its
        // roots against the CERTIFIED tip instead of re-streaming the spent set. The certificate binds `nullifier_root`
        // and `sparse_root` inside the tip summary, so a tip with either root swapped has another summary, the honest
        // certificate does not attest it (the door compares summaries), and a certificate re-labelled to the swapped
        // summary does not verify.
        let honest_tip = summary(1);
        assert_eq!(real.tip_summary, honest_tip, "the honest certificate attests the tip it folded");
        let swapped_sparse = summary_with(1, crate::poseidon2_compress::lanes_of(&[0, 1, 0, 0]), crate::poseidon2_compress::lanes_of(&[0, 0, 2, 0]));
        let swapped_nf = summary_with(1, crate::poseidon2_compress::lanes_of(&[0, 2, 0, 0]), crate::poseidon2_compress::lanes_of(&[0, 0, 1, 0]));
        assert_ne!(swapped_sparse, honest_tip, "a tip with another sparse_root has another summary");
        assert_ne!(swapped_nf, honest_tip, "a tip with another nullifier_root has another summary");
        assert!(!verify_whole_chain_cert(&WholeChainProof { tip_summary: swapped_sparse, ..real.clone() }), "⛔ a certificate re-labelled to a tip with a swapped sparse_root verified");
        assert!(!verify_whole_chain_cert(&WholeChainProof { tip_summary: swapped_nf, ..real.clone() }), "⛔ a certificate re-labelled to a tip with a swapped nullifier_root verified");
        eprintln!(
            "[cert] ⭐ honest 2-step certificate {} B (two steps incl. the genesis proof in {:.1?}), inherited + third step {} B (cumulative {:.1?}); the forged inheritance is refused natively and by the rows at row {:?}",
            real.step.bytes.len(),
            t_two,
            cont.step.bytes.len(),
            t_three,
            refused_at
        );
    }
}
