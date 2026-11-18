// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! **PQ-VDF block clock** — a post-quantum Verifiable Delay Function that paces block production with a
//! CONSTANT, unforgeable heartbeat. This is the greenfield PQ port of the old-tree MinRoot clock, carried
//! forward in the node's own KoalaBear field.
//!
//! WHY. A wall-clock spacing gate only *asks* an honest producer to wait — a fast or adversarial node can
//! ignore it, emit blocks back-to-back, and (because GHOSTDAG accepts parallel blocks) both inflate the DAG
//! width AND leak a variable, demand-correlated block rate (a timing/volume metadata leak — a digital-cash
//! violation). A VDF makes the interval a HARD, self-verifying minimum: every block carries the output of a
//! sequential MinRoot chain seeded from its parents, and a verifier that recomputes it rejects any block
//! that did not spend the delay. No node can outrun the heartbeat, so the block rate stays a fixed
//! constant regardless of load — the constant-cadence privacy invariant holds by construction.
//!
//! HEARTBEAT, NOT PACE-BY-DIFFICULTY. The interval is a CONSTANT (this VDF), governance-tunable by
//! re-pointing [`VDF_STEPS_PER_BLOCK`]; the PoUW difficulty (adaptive DAA) absorbs hardware drift SEPARATELY
//! so the interval never changes with demand. Adapting the *interval* to demand would leak volume — so we
//! never do; only difficulty adapts.
//!
//! CONSTRUCTION = **MinRoot** (Khovratovich et al.) over KoalaBear: the sequential (slow) step is a d-th
//! ROOT `x_{i+1} = (x_i + y_i)^{1/7}`, `y_{i+1} = x_i + i`; the cheap FORWARD relation is
//! `x_{i+1}^7 == x_i + y_i` (a degree-7 constraint — the same S-box the node's Poseidon2 uses, so the
//! whole-chain soundness folds into the EXISTING WHIR decider, never a standalone STARK). d=7 is a valid
//! permutation exponent because `gcd(7, p-1) = 1` (`p-1 = 2^24 · 127`).
//!
//! NO-GROWTH. [`VDF_STEPS_PER_BLOCK`] is a FIXED CONSTANT, never a tradeoff/growth axis: eval time, verify
//! time, and the 8-byte per-block output are all O(1) forever, independent of height/width/notes. The LIVE
//! tip gate is a cheap re-eval (a constant ~tens of ms — the ONLY per-tip cost); historical blocks are
//! covered by the WHIR decider fold and are NEVER re-eval'd (no slow monolithic whole-history path).
//!
//! PRIVACY. The VDF is a pure function of (parent VDF output, parent block hash) — a heartbeat tick
//! identical for every observer, carrying ZERO value/identity/note/amount information. Viewing the clock
//! reveals only height, which is already ambient.

/// KoalaBear prime `p = 2^31 - 2^24 + 1` (the node's field, matching [`crate::spend_frontier`]).
const KB_P: u64 = 2_130_706_433;
/// `p - 1`, the order of the multiplicative group — the modulus the S-box exponent and its inverse must
/// multiply to 1 under. Restored after a dead-code sweep removed it: `cargo check --lib` reports it unused
/// because its only consumer is the test that PROVES `VDF_D · VDF_ROOT_EXP ≡ 1 (mod p-1)`. A lib-scoped
/// "never used" is not evidence a constant is dead when a test depends on it.
const KB_P_MINUS_1: u64 = 2_130_706_432;
/// The MinRoot S-box exponent. `VDF_ROOT_EXP` is its inverse mod `p-1`, so raising to `VDF_D` then to
/// `VDF_ROOT_EXP` is the identity — that round trip is exactly what makes the VDF's forward step cheap to
/// verify and its inverse the sequential work. Verified numerically, not recalled: inverse(1_826_319_799,
/// 2_130_706_432) == 7.
const VDF_D: u64 = 7;
/// The d-th-ROOT exponent `e = 7^{-1} mod (p-1) = 1_826_319_799` (so `7·e ≡ 1 (mod p-1)`; asserted in
/// tests). Raising to `e` is the SLOW sequential direction; checking `x'^7 == x + y` is the cheap one.
const VDF_ROOT_EXP: u64 = 1_826_319_799;

/// The DEFAULT per-block VDF length — the genesis value of the governance-tunable `ChainParams::vdf_steps`
/// (single source of truth: `params::VDF_STEPS_DEFAULT` re-exports this). A CONSTANT heartbeat, never a growth
/// or tradeoff axis (no-growth pillar); the LIVE value is read from the governance-active params (retunable at
/// runtime, no re-genesis), every per-block VDF cost stays O(1). Must be a power of two `> 1`.
///
/// CALIBRATION (greenfield KoalaBear, release, measured ~230 ns/step): `2^18 = 262_144` ⇒ ≈ 64 ms of
/// sequential work — a real anti-outrun / anti-outsource floor that stays CHEAP to re-eval on the live tip
/// (~6% of a ~1.1 s interval). The delay `D` trades against the re-eval verify cost, so raising `D` toward
/// the full inter-block interval requires the succinct WHIR-decider verify (so verify cost stops tracking
/// `D`) — see the module docs. Difficulty (adaptive DAA), NOT this constant, absorbs demand.
pub const VDF_STEPS_PER_BLOCK: u64 = 262_144;

/// Reference sequential-eval cost per MinRoot step (greenfield KoalaBear, release build, measured). A
/// governance retarget of [`VDF_STEPS_PER_BLOCK`] to hit a wall-time target divides the target by this;
/// hardware varies, so the LIVE value stays the pinned constant. The interval stays CONSTANT (never
/// demand-driven) — only its calibrated length is ever retuned.
pub const VDF_REF_NS_PER_STEP: u64 = 230;

/// A VDF clock state / output — the MinRoot pair `(x, y)` as canonical KoalaBear limbs (each `< KB_P`, so a
/// `u32` holds them). The block header binds the OUTPUT (8 bytes); the seed is re-derived from the parent.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct VdfState {
    pub x: u32,
    pub y: u32,
}

impl VdfState {
    /// The 8-byte on-block encoding (`x ‖ y`, big-endian) the producer splices into the header and the
    /// add-gate re-derives.
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&self.x.to_be_bytes());
        b[4..8].copy_from_slice(&self.y.to_be_bytes());
        b
    }

    /// Decode the 8-byte on-block encoding, rejecting non-canonical limbs (fail-closed — a limb `>= KB_P`
    /// is not a valid field element and cannot be a real VDF output).
    pub fn from_bytes(b: &[u8; 8]) -> Option<Self> {
        let x = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let y = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        if (x as u64) < KB_P && (y as u64) < KB_P {
            Some(Self { x, y })
        } else {
            None
        }
    }
}

#[inline]
fn kb_add(a: u64, b: u64) -> u64 {
    let s = a + b;
    if s >= KB_P {
        s - KB_P
    } else {
        s
    }
}

#[inline]
fn kb_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % KB_P as u128) as u64
}

/// `base^e mod p` by square-and-multiply. For the d-th root the exponent is ~`2^31`, so each root is a fixed
/// ~31-squaring computation; the SEQUENTIALITY comes from the chain (step `i+1` needs step `i`'s root),
/// which no parallelism can shortcut.
fn kb_pow(base: u64, mut e: u64) -> u64 {
    let mut acc: u64 = 1;
    let mut b = base % KB_P;
    while e > 0 {
        if e & 1 == 1 {
            acc = kb_mul(acc, b);
        }
        b = kb_mul(b, b);
        e >>= 1;
    }
    acc
}

/// The slow MinRoot step: the unique 7th root of `v` (i.e. `v^{1/7}`), the sequential work unit.
#[inline]
fn dth_root(v: u64) -> u64 {
    kb_pow(v, VDF_ROOT_EXP)
}

/// Run the sequential MinRoot chain for `steps` rounds from `seed`, returning the final `(x, y)`.
///
/// Round `i` (`0 <= i < steps`):
///   * `x_{i+1} = (x_i + y_i)^{1/7}`  — the SLOW root (the delay; on the critical path, un-parallelizable)
///   * `y_{i+1} = x_i + i`
pub fn eval(seed: VdfState, steps: u64) -> VdfState {
    let mut x = seed.x as u64;
    let mut y = seed.y as u64;
    let mut i: u64 = 0;
    while i < steps {
        let nx = dth_root(kb_add(x, y));
        let ny = kb_add(x, i % KB_P);
        x = nx;
        y = ny;
        i += 1;
    }
    VdfState {
        x: x as u32,
        y: y as u32,
    }
}

/// Like [`eval`] but returns the full witness trace `[seed, state_1, .., state_steps]` (`steps + 1` rows) —
/// the per-row witness the WHIR decider folds to prove the whole-chain VDF timeline in O(1). Consecutive
/// rows satisfy the degree-7 forward relation `row[i+1].x^7 == row[i].x + row[i].y` and
/// `row[i+1].y == row[i].x + i`.
pub fn eval_with_trace(seed: VdfState, steps: u64) -> Vec<VdfState> {
    let mut rows = Vec::with_capacity(steps as usize + 1);
    rows.push(seed);
    let mut x = seed.x as u64;
    let mut y = seed.y as u64;
    let mut i: u64 = 0;
    while i < steps {
        let nx = dth_root(kb_add(x, y));
        let ny = kb_add(x, i % KB_P);
        x = nx;
        y = ny;
        rows.push(VdfState {
            x: x as u32,
            y: y as u32,
        });
        i += 1;
    }
    rows
}

/// Derive block N's VDF seed from block N-1's VDF OUTPUT and a `challenge` (the parent block hash), via the
/// node's canonical Poseidon2 ([`crate::spend_frontier::poseidon_pair`]). This CHAINS the timeline: N's
/// input binds to N-1's output, so the clock cannot be precomputed ahead of the parent, forged, or
/// reordered. The challenge is the parent hash (fixed before this block's own mutable fields — non-circular).
pub fn derive_seed(parent_out: VdfState, challenge: &[u8; 32]) -> VdfState {
    // `lanes_of` pads to the digest's CURRENT lane count — the one place this file would otherwise
    // carry a literal whose length has to be edited every time the digest width moves.
    let po = usdm_decider::poseidon2_compress::lanes_of(&[parent_out.x as u64, parent_out.y as u64]);
    let ch = crate::spend_frontier::cm_bytes_to_leaf(challenge);
    let d = crate::spend_frontier::poseidon_pair(po, ch);
    VdfState {
        x: (d[0] % KB_P) as u32,
        y: (d[1] % KB_P) as u32,
    }
}

/// PRODUCER: compute block N's VDF output — `eval(derive_seed(parent_out, parent_hash), steps)`. The producer
/// splices `output.to_bytes()` into the header. This is the sequential delay it MUST spend. `steps` is the
/// GOVERNANCE-ACTIVE length (`ChainParams::vdf_steps`), NOT a compile-time constant — so the heartbeat is
/// runtime-tunable without a re-genesis.
pub fn block_vdf(parent_out: VdfState, parent_hash: &[u8; 32], steps: u64) -> VdfState {
    eval(derive_seed(parent_out, parent_hash), steps)
}

/// LIVE per-block HEARTBEAT GATE (add-path): recompute block N's VDF from the parent at the GOVERNANCE-ACTIVE
/// `steps` (`ChainParams::vdf_steps`) and require the block's `claimed` output to match EXACTLY. Rejects
/// (fail-closed) any block whose VDF is short, absent, tampered, or not chained to the parent — so a producer
/// cannot emit faster than the heartbeat. A CONSTANT ~tens-of-ms cost, applied only to the new tip; history
/// rides the WHIR decider fold, never re-eval'd here.
pub fn verify_block_vdf(
    parent_out: VdfState,
    parent_hash: &[u8; 32],
    claimed: VdfState,
    steps: u64,
) -> bool {
    block_vdf(parent_out, parent_hash, steps) == claimed
}

/// The genesis VDF seed — a deterministic function of the network tag only (no per-node input), so every
/// node's clock starts identically. Genesis carries this as its "parent output".
pub fn genesis_vdf_out(network: &str) -> VdfState {
    let h = crate::hash::Hash32::hash(format!("MONEROUSD_VDF_GENESIS::{network}").as_bytes());
    let leaf = crate::spend_frontier::cm_bytes_to_leaf(h.as_bytes());
    VdfState {
        x: (leaf[0] % KB_P) as u32,
        y: (leaf[1] % KB_P) as u32,
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// The d-th-root exponent is the true inverse of the S-box exponent: `7 · e ≡ 1 (mod p-1)`.
    #[test]
    fn root_exponent_inverts_the_sbox() {
        let prod = (VDF_D as u128) * (VDF_ROOT_EXP as u128);
        assert_eq!(prod % (KB_P_MINUS_1 as u128), 1, "7·e ≡ 1 (mod p-1)");
        // ...and functionally: (a^7)^e == a and (a^e)^7 == a for many field elements.
        for a in [2u64, 3, 7, 12345, KB_P - 1, KB_P - 2, 1_000_000] {
            let up = kb_pow(a, VDF_D);
            assert_eq!(kb_pow(up, VDF_ROOT_EXP), a, "(a^7)^e == a for a={a}");
            let root = dth_root(a);
            assert_eq!(kb_pow(root, VDF_D), a, "(a^{{1/7}})^7 == a for a={a}");
        }
    }

    /// The constant is a power of two `> 1` (a well-formed MinRoot length).
    #[test]
    fn steps_constant_is_wellformed() {
        assert!(VDF_STEPS_PER_BLOCK > 1 && VDF_STEPS_PER_BLOCK.is_power_of_two());
    }

    /// `eval` is deterministic and every output limb is canonical.
    #[test]
    fn eval_is_deterministic_and_canonical() {
        let seed = VdfState { x: 12345, y: 67890 };
        let a = eval(seed, 512);
        let b = eval(seed, 512);
        assert_eq!(a, b, "same seed+steps ⇒ same output");
        assert!(
            (a.x as u64) < KB_P && (a.y as u64) < KB_P,
            "canonical limbs"
        );
    }

    /// The trace satisfies the degree-7 FORWARD relation at every row — the exact low-degree constraint the
    /// WHIR decider will enforce (proving the eval and the constraint agree; the decider's soundness seam).
    #[test]
    fn trace_satisfies_the_degree7_forward_relation() {
        let seed = VdfState { x: 111, y: 222 };
        let steps = 200u64;
        let rows = eval_with_trace(seed, steps);
        assert_eq!(rows.len() as u64, steps + 1);
        assert_eq!(rows[0], seed, "row 0 is the seed");
        for i in 0..steps as usize {
            let (cur, nxt) = (rows[i], rows[i + 1]);
            // x_{i+1}^7 == x_i + y_i
            assert_eq!(
                kb_pow(nxt.x as u64, VDF_D),
                kb_add(cur.x as u64, cur.y as u64),
                "forward x-relation @ row {i}"
            );
            // y_{i+1} == x_i + i
            assert_eq!(
                nxt.y as u64,
                kb_add(cur.x as u64, i as u64 % KB_P),
                "forward y-relation @ row {i}"
            );
        }
        // The final row is exactly what `eval` returns.
        assert_eq!(*rows.last().unwrap(), eval(seed, steps));
    }

    /// HONEST end-to-end at the PINNED constant: a real block VDF verifies.
    #[test]
    fn honest_block_vdf_verifies_at_the_pinned_constant() {
        let parent_out = VdfState { x: 9, y: 99 };
        let parent_hash = [0x5au8; 32];
        let out = block_vdf(parent_out, &parent_hash, VDF_STEPS_PER_BLOCK);
        assert!(
            verify_block_vdf(parent_out, &parent_hash, out, VDF_STEPS_PER_BLOCK),
            "honest VDF accepts"
        );
    }

    /// TAMPER — a forged output is rejected (a producer cannot fake the delay).
    #[test]
    fn tampered_output_is_rejected() {
        let parent_out = VdfState { x: 9, y: 99 };
        let parent_hash = [0x5au8; 32];
        let out = block_vdf(parent_out, &parent_hash, VDF_STEPS_PER_BLOCK);
        let forged = VdfState {
            x: out.x.wrapping_add(1),
            y: out.y,
        };
        assert!(
            !verify_block_vdf(parent_out, &parent_hash, forged, VDF_STEPS_PER_BLOCK),
            "forged output rejects"
        );
        let forged_y = VdfState {
            x: out.x,
            y: out.y ^ 0x1,
        };
        assert!(
            !verify_block_vdf(parent_out, &parent_hash, forged_y, VDF_STEPS_PER_BLOCK),
            "forged y rejects"
        );
    }

    /// SHORT-RUN — an output from fewer sequential rounds than the heartbeat is rejected (this is the
    /// anti-outrun property: you cannot produce a valid block by waiting less).
    #[test]
    fn short_run_is_rejected() {
        let parent_out = VdfState { x: 4, y: 44 };
        let parent_hash = [0x11u8; 32];
        let seed = derive_seed(parent_out, &parent_hash);
        let short = eval(seed, VDF_STEPS_PER_BLOCK - 1); // one round shy of the heartbeat
        assert!(
            !verify_block_vdf(parent_out, &parent_hash, short, VDF_STEPS_PER_BLOCK),
            "an under-length VDF cannot pass — the interval is a hard minimum"
        );
    }

    /// SEED CHAINING binds the timeline: a different parent OUTPUT or a different challenge yields a
    /// different seed (so the clock can't be reordered or replayed across blocks), and it is deterministic.
    #[test]
    fn seed_chaining_binds_parent_and_challenge() {
        let p1 = VdfState { x: 1, y: 2 };
        let p2 = VdfState { x: 1, y: 3 };
        let c1 = [0x01u8; 32];
        let c2 = [0x02u8; 32];
        assert_eq!(derive_seed(p1, &c1), derive_seed(p1, &c1), "deterministic");
        assert_ne!(
            derive_seed(p1, &c1),
            derive_seed(p2, &c1),
            "binds parent output"
        );
        assert_ne!(
            derive_seed(p1, &c1),
            derive_seed(p1, &c2),
            "binds challenge"
        );
    }

    /// A block whose VDF was chained to the WRONG parent is rejected (timeline forgery fails).
    #[test]
    fn wrong_parent_chain_is_rejected() {
        let real_parent = VdfState { x: 7, y: 70 };
        let other_parent = VdfState { x: 8, y: 80 };
        let parent_hash = [0x33u8; 32];
        let out = block_vdf(real_parent, &parent_hash, VDF_STEPS_PER_BLOCK);
        assert!(
            !verify_block_vdf(other_parent, &parent_hash, out, VDF_STEPS_PER_BLOCK),
            "wrong-parent chain rejects"
        );
    }

    /// GOVERNANCE TUNABILITY: the SAME parent verifies under whatever `steps` the block was produced at, and a
    /// block produced at one heartbeat length is REJECTED when checked at a different length — so a governance
    /// retune is a hard consensus rule (a producer can't reuse an old-length VDF after the length changes).
    #[test]
    fn vdf_length_is_governance_bound_not_fixed() {
        let parent_out = VdfState { x: 21, y: 210 };
        let parent_hash = [0x77u8; 32];
        let short_len = 1u64 << 12; // a governance-legal alternative length
        let out_short = block_vdf(parent_out, &parent_hash, short_len);
        assert!(
            verify_block_vdf(parent_out, &parent_hash, out_short, short_len),
            "verifies at its own length"
        );
        assert!(
            !verify_block_vdf(parent_out, &parent_hash, out_short, VDF_STEPS_PER_BLOCK),
            "an output made at a different heartbeat length is rejected — the length is a live consensus rule"
        );
    }

    /// The 8-byte on-block encoding round-trips, and non-canonical bytes are rejected (fail-closed decode).
    #[test]
    fn output_encoding_roundtrips_and_rejects_noncanonical() {
        let s = VdfState {
            x: 123_456,
            y: 2_130_706_432,
        };
        assert_eq!(VdfState::from_bytes(&s.to_bytes()), Some(s));
        let bad = [0xffu8; 8]; // 0xffffffff >= KB_P ⇒ not a field element
        assert_eq!(
            VdfState::from_bytes(&bad),
            None,
            "non-canonical limbs reject"
        );
    }

    /// Genesis seed is deterministic per network and differs across networks (no chain-split seed collision).
    #[test]
    fn genesis_vdf_out_is_deterministic_per_network() {
        assert_eq!(genesis_vdf_out("testnet"), genesis_vdf_out("testnet"));
        assert_ne!(genesis_vdf_out("testnet"), genesis_vdf_out("mainnet"));
    }
}
