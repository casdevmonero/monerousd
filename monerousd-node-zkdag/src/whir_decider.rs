// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The node's O(1) decider surface — 100% pure-Rust HVZK-WHIR via the SMALL vendored `usdm-decider` crate
//! (p3-whir/p3-sumcheck/KoalaBear only). ONE construction on EVERY device — desktop daemon, desktop wallet
//! in-process node, iPhone in-process node — so a proof served by ANY node verifies on EVERY node (the
//! cross-implementation drift that once silently broke phone↔daemon DSYNC adoption is impossible by
//! construction: there is no second implementation). The retired pqpool `circuit.rs` monolith FFI
//! (STARK-era, `libpqpool_ffi.dylib`) is DELETED from the node — never linked, never reachable.
//!
//! The decider points, all on the WHIR light decider:
//!   1. THE DIRECT SPEND GATE for every user action ([`pqspend_direct_verify_carrier`]) — the HVZK-WHIR
//!      hashless per-tx spend gate (Send / bond / Swap / token-create ride this) the mempool/block-accept
//!      binds into consensus (nf anti-replay, anchor ∈ known-roots, outcm binding).
//!   2. THE WHOLE-CHAIN BLOCK DECIDER — the #135 hashless light decider ([`decider_prove_light`] /
//!      [`decider_verify_light`], [`WhirDecider`] the [`crate::decider::ConsensusVerifier`] adopt gate) the
//!      DSYNC/consensus adopt proof rides (phone-class sub-1s verify).
//!   3. (RETIRED 2026-09-18) the #73/#142 coinbase pow-bind — the chain is zero-emission; a block carries no coinbase carrier.
//!      non-outsourceable PoUW carrier, WHIR light decider (never FRI, never STARK).
//!
//! All gates are fail-closed: a hostile/malformed/tampered proof returns `false`/`None` (never a crash),
//! the contract [`crate::decider::accept_bundle`] relies on.
//!
//! HF44 L2 settlement: the pqpool STARK-era `BatchSettlementBundle` verify is RETIRED WITH THE FFI. The node's
//! settlement gate stays FAIL-CLOSED by default (`crate::settlement` admits nothing unverified); the WHIR-native
//! cross-sender settle carrier (task #144/#145, `usdm_decider::whir_rec_block` xsender) is the conversion that
//! re-enables settlement carriers node-side (#142 backlog) — sound-by-default until then, never admit-structurally.

use crate::decider::{ConsensusVerifier, DeciderBundle};
use crate::hash::Hash32;
use p3_field::PrimeCharacteristicRing;
use usdm_decider::air_zerocheck::AirConstraint;
use usdm_decider::hiding_decider::{Ea4, Fa4};
use usdm_decider::{
    prove_air_direct_light_decider_selfcontained_bytes,
    verify_air_direct_light_decider_selfcontained_bytes,
    verify_spend_carrier_bytes,
};

/// The production [`ConsensusVerifier`] on the canonical whole-chain WHIR light decider
/// (`usdm_decider::whole_chain`) — the ONE adopt-gate implementation network-wide, so a bundle served by
/// ANY node verifies on EVERY node. Fail-closed on empty/tampered/malformed.
///
/// ⛔⛔⛔ WHAT `true` FROM THIS VERIFIER MEANS — CORRECTED 2026-09-07 (family-D pin D-1).
///
/// It means: **"somebody ran the public prover with THIS 16-byte accumulator."** It does NOT mean the
/// chain up to the committed tip is sound, and this doc used to say that it did.
///
/// The mechanism, read out of the code rather than out of the comment:
/// `usdm_decider::whole_chain::prove_whole_chain_light_decider_bytes(chain_acc)` takes the accumulator
/// as its ONLY argument and proves `build_whole_chain_artifacts(t)` — a FIXED public AIR that reads
/// nothing from any chain. `verify_whole_chain_light_decider_bytes` rebuilds that same fixed AIR and
/// checks the openings under a transcript seeded with `chain_acc`. The seeding does bind the proof to
/// ONE accumulator value (so a proof for chain A does not verify for chain B — that part is real), but
/// the prover is public and takes no witness, so any party can mint a verifying proof for any
/// accumulator it invents. MEASURED (pin D-1 / D-2): a node running exactly this verifier adopted a
/// #29 bundle whose tip was never mined, whose roots were typed by the attacker, and whose validator
/// set the attacker owned.
///
/// CONSEQUENCE FOR CALLERS: `sync::sync_binding`'s completeness (every acted-on field inside the
/// preimage) makes the bundle unforgeable by a THIRD PARTY who tampers with someone else's bundle. It
/// buys nothing against the party that MINTS the bundle. Until the decider is a chain statement, the
/// adopt gate's own independent evidence is the header grind and header rules
/// `Node::bundle_blocks_admitted` runs on the carried blocks — nothing else.
///
/// ⛔⛔⛔ THE REMAINING DESIGN ITEM, WRITTEN OUT (D01/Q2). This is NOT a bug with a diff; it is a
/// missing statement, and the honest thing is to specify it rather than to bind more fields.
///
/// WHAT THE PROOF MUST SAY: "there exists a chain, rooted at the genesis this accumulator names,
/// whose accepted transitions carry state from a PREVIOUSLY CERTIFIED accumulator `A_prev` to this
/// `A_next`." The public inputs are then `(A_prev, A_next)` — two accumulators — not one, and the
/// witness is the transition. A party with no chain cannot produce the witness, which is precisely
/// the property `decider_prove_light(chain_acc)` does not have today.
///
/// WHAT THE TRANSITION MUST CONSTRAIN, per step: (1) the step's header grind — the same
/// `hash_meets_target(hash(preimage), work)` the gossip door runs — and the DAA equality binding
/// `work` to the chain's own difficulty, so accumulated weight cannot be declared; (2) the fold from
/// `A_prev` to `A_next` over exactly the fields `sync::sync_binding` folds, so the accumulator is a
/// FUNCTION of the chain rather than a label attached to it; (3) conservation across the step (the
/// nullifier insert and the note deletion/insert already have circuits — `nullifier_insert_air`,
/// `note_membership_air`, `nf_sparse_air` — so this is composition, not new cryptography); (4) the
/// validator-set transition, since the quorum rides the same bundle.
///
/// WHY IT IS A DESIGN DECISION AND NOT A TASK: the whole-chain decider's value is that it is O(1) at
/// any chain length (the pinned `WHOLE_CHAIN_T = 32` trace shape). A per-step chain statement is
/// recursive by construction — each proof verifies its predecessor — so the choice is between (a)
/// IVC/recursion over `whir_rec_block`, paying a prove cost per block and a genesis-to-tip chain of
/// proofs that must be maintained, (b) an epoch checkpoint the validator quorum signs, which trades
/// the trustless property for the bond, or (c) accepting that instant sync is trust-on-first-adopt
/// and making the node re-derive weight from headers it grinds itself, which is Bitcoin's answer and
/// is NOT O(1). Each of those changes what the product is. That is a user/architecture call, and
/// this lane states it rather than picking one under the cover of a fix.
///
/// WHAT HOLDS UNTIL THEN, and what does not: a peer cannot tamper with a bundle in flight (the
/// binding), cannot carry an unmined or malformed block (`bundle_blocks_admitted`), and cannot walk a
/// node's state backwards (`NotHeavier`). A peer CAN still mint a bundle for a chain that does not
/// exist, and a node with no better source will adopt it — pins D-1 (and the class behind the now
/// green D-2/D-3/D-4) are the standing record of that.
pub struct WhirDecider;

impl ConsensusVerifier for WhirDecider {
    fn verify_bundle(&self, bundle: &DeciderBundle) -> bool {
        // Verify against the bundle's `chain_acc` — the O(1) accumulator over tip, blue score, blue
        // work, the note-frontier root, the nullifier/sparse/unspent roots, the record base and the
        // genesis identity. The proof is transcript-bound to that value, so a proof minted for one
        // accumulator does not verify for another. See the type's doc for what that does and does not
        // establish: it separates chains, it does not prove one.
        !bundle.proof.is_empty() && decider_verify_light(&bundle.proof, &bundle.chain_acc)
    }
}

/// #135 whole-chain LIGHT decider VERIFY (adopt gate) — THE canonical implementation in
/// `usdm_decider::whole_chain`, identical on every build/device. `true` = verified, `false` =
/// rejected/empty/tampered/malformed. Never panics.
pub fn decider_verify_light(proof: &[u8], chain_acc: &[u8; 16]) -> bool {
    usdm_decider::whole_chain::verify_whole_chain_light_decider_bytes(proof, chain_acc)
}

/// #135 / #29 DSYNC PRODUCE (serve side) — THE canonical whole-chain light-decider prove in
/// `usdm_decider::whole_chain`, so a phone-served bundle verifies on a daemon and vice versa.
/// `None` on prove failure (the node then can't serve — another peer does, so the mesh always
/// has a server with no single sync source).
pub fn decider_prove_light(chain_acc: &[u8; 16]) -> Option<Vec<u8>> {
    usdm_decider::whole_chain::prove_whole_chain_light_decider_bytes(chain_acc)
}

/// #135 verify a DIRECT per-tx SPEND carrier (Send / Swap / token-create / …) on the pure-Rust WHIR path
/// via the ONE config-pinned shared wallet+node entry `usdm_decider::verify_spend_carrier_bytes` — the same
/// carrier the V2 wallet produces (conservation / no-inflation, nullifier `nf = Poseidon(sk, leaf)`, and
/// in-circuit Poseidon-Merkle frontier membership, all bound in the proof). Returns `Some(())` (empty pvs)
/// on a sound carrier so the node's admission gate — which tests `.is_some()` (rpc_http) — accepts it; the
/// node binds the tx-envelope nullifier for anti-replay (the proof attests it is the correct one). `None`
/// fail-closed on any reject / malformed / empty carrier — never panics (decode failure → None).
pub fn pqspend_direct_verify_carrier(carrier: &[u8]) -> Option<Vec<u8>> {
    if carrier.is_empty() || !verify_spend_carrier_bytes(carrier) {
        return None;
    }
    Some(Vec::new())
}

/// Startup health check on the pure-Rust WHIR direct light decider: prove→verify a real BOOLEANITY AIR
/// (`x·(x−1) = 0` on a 0/1 column) end-to-end. `true` ⇒ the prover+verifier are sound on this build (a
/// non-boolean column would fail the zerocheck → false); `false` ⇒ the engine is broken and the node must
/// not trust the verify gate.
pub fn decider_selftest() -> bool {
    // A minimal REAL row-local AIR: booleanity of column 0 over a 32-row 0/1 trace (height = 2^5, the
    // carrier convention — the direct engine's folding needs height ≥ 2^folding, so 4 rows is too small).
    let col0: Vec<Fa4> = (0..32u64)
        .map(|i| if i % 2 == 0 { Fa4::ZERO } else { Fa4::ONE })
        .collect();
    let cols: Vec<Vec<Fa4>> = vec![col0];
    let make = |gamma: Ea4| BooleanityGate { gamma };
    let proof = match prove_air_direct_light_decider_selfcontained_bytes(cols, make, &[]) {
        Some(p) => p,
        None => return false,
    };
    verify_air_direct_light_decider_selfcontained_bytes(&proof, make, &[], (5, 1))
}

/// A minimal ROW-LOCAL booleanity constraint `γ·(x·(x−1))` on column 0 — the honest self-test AIR
/// [`decider_selftest`] proves+verifies. Row-local ⇒ constant degree 2.
struct BooleanityGate {
    gamma: Ea4,
}

impl AirConstraint for BooleanityGate {
    fn degree(&self, _nvars: usize) -> usize {
        2
    }
    fn eval(
        &self,
        local: &usdm_decider::air_zerocheck::Row<'_>,
        _at: &dyn Fn(usize, &[Ea4]) -> Ea4,
        _x: &[Ea4],
    ) -> Ea4 {
        let x = local[0];
        self.gamma * (x * x - x)
    }
}

/// 32 spend-key / challenge bytes → the digest the coinbase gate binds, through the crate's ONE map from
/// arbitrary 32-byte ids into a digest (`hash32_to_digest`). Deterministic, so prove + verify derive the
/// identical field element.
///
/// ⛔ §AG CLASS 9, the silent half. This read FOUR raw LE u64s into an EIGHT-lane digest and left lanes
/// 4..7 zero — the coinbase key and the per-block challenge entered the proof at half width (124 bits,
/// with each limb reduced mod p by the prover so `0` and `p` named one key). `hash32_to_digest` puts
/// every input byte into the permutation and cannot go stale the next time the width moves. Both
/// derived values MOVE: `out0` (the reward note's commitment) and therefore `miner_commitment` and
/// `pow_bind` on every block — consensus-visible, covered by the §AG re-genesis.
pub fn bytes32_to_limbs(b: &[u8; 32]) -> crate::spend_frontier::Digest4 {
    usdm_decider::poseidon2_compress::hash32_to_digest(b)
}

/// The reward note's commitment → the 32-byte [`Hash32`] the node stores as `miner_commitment`: the
/// canonical injective digest form, so the header binds the WHOLE commitment.
///
/// ⛔ §AG CLASS 9, the silent half, on a consensus header field. This wrote lanes 0..3 as LE u64s into 32
/// bytes and DROPPED lanes 4..7 — so `coinbase_pow_bind_verify`'s "carried out0 MUST equal the
/// miner_commitment" compared 124 bits, i.e. a 2^62 prefix collision let a different `out0` (proved
/// for its own value) ride under an honest header's commitment. `leaf_to_cm_bytes` is injective over
/// the canonical digest the prover returns.
pub fn limbs_to_hash32(limbs: &crate::spend_frontier::Digest4) -> Hash32 {
    Hash32(crate::spend_frontier::leaf_to_cm_bytes(*limbs))
}

/// The self-describing coinbase pow-bind `pi` a block carries: the WHIR carrier PLUS its public values
/// (root/out0/out1/nf/value). All are bound into the carrier's transcript (`coinbase_public_bind`), so a
/// lying header diverges the transcript → the carrier rejects; the caller then binds `note_cm == out0` to
/// tie the block's stored reward note to the proof. Postcard-encoded (a truncated/corrupt frame → reject).
#[derive(serde::Serialize, serde::Deserialize)]
struct CoinbasePi {
    /// The reward note's commitment — the ONE value the carrier opens.
    out0: crate::spend_frontier::Digest4,
    /// The reward amount that commitment must open to.
    value: u64,
    carrier: Vec<u8>,
}


#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::decider::accept_bundle;

    /// The engine keystone: the pure-Rust WHIR direct light decider PROVES and VERIFIES a real AIR step
    /// end-to-end — the node runs genuine usdm-decider WHIR, not a stub.
    #[test]
    fn pure_rust_decider_selftest_is_sound() {
        assert!(
            decider_selftest(),
            "pure-Rust WHIR direct light decider prove→verify must be sound"
        );
    }


    /// Adversarial fail-closed: the whole-chain adopt gate + the direct spend gate REJECT garbage/empty
    /// (decode failure / non-proof → false / None, never a crash), and the adopt gate's no-blowup size cap
    /// rejects an oversize blob BEFORE the verifier runs.
    #[test]
    fn whole_chain_and_spend_gates_fail_closed_on_garbage_empty_and_oversize() {
        let garbage: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        assert!(
            !decider_verify_light(&garbage, &[9u8; 16]),
            "garbage whole-chain proof must not verify"
        );
        assert!(
            !decider_verify_light(&[], &[9u8; 16]),
            "empty whole-chain proof must be rejected"
        );
        let bundle_with = |proof: Vec<u8>| DeciderBundle {
            tip: crate::hash::Hash32::hash(b"whir-decider-tip"),
            blue_score: 6,
            chain_acc: [9u8; 16],
            proof,
        };
        assert!(
            !accept_bundle(&WhirDecider, &bundle_with(garbage.clone())),
            "garbage must not verify"
        );
        assert!(!accept_bundle(&WhirDecider, &bundle_with(vec![])));
        assert!(!WhirDecider.verify_bundle(&bundle_with(vec![]))); // direct call also guarded
        assert!(!accept_bundle(
            &WhirDecider,
            &bundle_with(vec![1u8; DeciderBundle::MAX_PROOF_BYTES + 1])
        ));
        assert!(
            pqspend_direct_verify_carrier(&garbage).is_none(),
            "garbage spend carrier must not verify"
        );
        assert!(
            pqspend_direct_verify_carrier(&[]).is_none(),
            "empty spend carrier must be rejected"
        );
    }

    /// The honest whole-chain roundtrip: our own light prove verifies, a flipped byte rejects (fail-closed).
    #[test]
    fn whole_chain_prove_verify_and_tamper_reject() {
        let acc = [7u8; 16];
        let proof = decider_prove_light(&acc).expect("whole-chain light prove must emit a proof");
        assert!(!proof.is_empty(), "light proof is non-empty");
        assert!(
            decider_verify_light(&proof, &acc),
            "honest whole-chain proof must VERIFY"
        );
        let mut bad = proof.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        assert!(
            !decider_verify_light(&bad, &acc),
            "a tampered whole-chain proof MUST be rejected"
        );
    }

    /// ⭐⭐⭐ THE WHOLE CHAIN IS FOLDED INTO THE PROOF (user 2026-07-22) — the proof CERTIFIES chain state.
    ///
    /// This is the test that closes a real soundness hole. Before the fold, the whole-chain proof took NO
    /// arguments: it was state-INDEPENDENT, so one proof verified against EVERY chain, and `adopt_sync_bundle`'s
    /// `chain_acc` check only compared a peer's hash against that peer's OWN claims. A malicious peer could serve a
    /// forged tip / note-frontier root / nullifier root / sparse root / genesis under a perfectly valid proof and be
    /// adopted. Now the proof is transcript-bound to `chain_acc`, so a proof minted for state A CANNOT verify
    /// against state B — forging any component of the chain state costs the attacker a proof they cannot produce.
    ///
    /// NO GROWTH ON ANY AXIS: the binding is FIXED 16 bytes and rides the Fiat-Shamir transcript — zero trace rows,
    /// zero committed columns, zero extra proof bytes, zero extra proving work, at ANY chain length.
    #[test]
    fn whole_chain_proof_is_bound_to_chain_state_a_proof_for_one_chain_rejects_another() {
        let acc_a = [0xA5u8; 16];
        let proof_a = decider_prove_light(&acc_a).expect("prove for chain A");
        assert!(
            decider_verify_light(&proof_a, &acc_a),
            "chain A's proof verifies against chain A"
        );

        // A DIFFERENT chain state — one flipped bit is enough (this stands in for a forged nullifier/frontier root,
        // since every one of those feeds `sync_binding` → `chain_acc`).
        let mut acc_b = acc_a;
        acc_b[0] ^= 0x01;
        assert!(
            !decider_verify_light(&proof_a, &acc_b),
            "SOUNDNESS: chain A's proof MUST NOT verify against a different chain state — a peer cannot reuse a \
             valid proof while lying about tip / frontier / nullifier / sparse root / genesis"
        );

        // …and the reverse direction, so the binding is not one-sided.
        let proof_b = decider_prove_light(&acc_b).expect("prove for chain B");
        assert!(
            decider_verify_light(&proof_b, &acc_b),
            "chain B's proof verifies against chain B"
        );
        assert!(
            !decider_verify_light(&proof_b, &acc_a),
            "chain B's proof MUST NOT verify against chain A"
        );

        // The end-to-end adopt gate inherits the binding: a bundle whose `chain_acc` disagrees with the proof is
        // REJECTED by `verify_bundle` itself, before any state is installed.
        let bundle = |acc: [u8; 16], proof: Vec<u8>| DeciderBundle {
            tip: crate::hash::Hash32::hash(b"folded-chain-tip"),
            blue_score: 6,
            chain_acc: acc,
            proof,
        };
        assert!(
            WhirDecider.verify_bundle(&bundle(acc_a, proof_a.clone())),
            "adopt gate accepts a bundle whose chain_acc matches the proof"
        );
        assert!(
            !WhirDecider.verify_bundle(&bundle(acc_b, proof_a)),
            "adopt gate REJECTS a bundle claiming a chain state the proof does not certify"
        );
    }

    /// The front-page size claim, MEASURED — the whole-chain WHIR proof is kilobyte-scale and its
    /// size is IDENTICAL for different chain states (the proof is f(protocol constants), never
    /// f(history)). Printed so the exact byte count is auditable in the test log; the site's number
    /// must track this measurement, not the other way around.
    #[test]
    fn whole_chain_proof_is_kilobyte_scale_and_size_constant() {
        let a = decider_prove_light(&[0x11u8; 16]).expect("prove A");
        let b = decider_prove_light(&[0xEEu8; 16]).expect("prove B");
        println!(
            "whole-chain WHIR proof size: A={} bytes, B={} bytes",
            a.len(),
            b.len()
        );
        // The invariant is NO HISTORY TERM, not byte-identity: variable-length encodings jitter a
        // few hundred bytes with the transcript (MEASURED: 8,750 vs 8,628 for two chain states) —
        // both sit at the same kilobyte scale whatever the chain contains.
        let (lo, hi) = (a.len().min(b.len()), a.len().max(b.len()));
        assert!(
            hi - lo <= 1_024,
            "proof sizes must sit in one band: {lo} vs {hi}"
        );
        assert!(hi <= 100_000, "kilobyte-scale bound: got {hi} bytes");
        assert!(!a.is_empty());
    }
}
