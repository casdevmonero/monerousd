// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE CHAIN'S TIMING, ONE SOURCE — the measured frame, the transport constants, and the two rates derived from them (the
//! production relay floor and the mesh's block-rate target), as PURE arithmetic with no dependency. [`crate::dag`] re-exports
//! them (their derivation and the measurements are documented there), and [`crate::sat_schedule`] lays the SAT issuance on
//! [`MESH_TARGET_SPACING_MS`] from here, so the schedule follows the chain's timing by construction: `kani-proofs` path-includes
//! this file beside `sat_schedule.rs`, and no literal copy of the target exists anywhere.
//!
//! MEASURED why (2026-11-16): `sat_schedule` held its target as a hand-copied literal (5,322 ms) so the model check could read
//! it without `dag`; c183575b re-derived the target to 3,221 ms from a re-measured frame and the literal stayed, so blocks came
//! 1.65× faster than the schedule was laid for (SAT issuing 1.65× faster per year than §BR-13 approved) while the one pin that
//! compared them sat red. One source makes that disagreement unrepresentable.
//! SCALE: compile-time constants; nothing grows. AI RESISTANCE: (b) code — every node compiles the same constants (consensus).

/// Three onion legs (announce, pull, deliver) at ~600 ms each.
pub(crate) const RELAY_ROUND_LEGS_MS: u64 = 3 * 600;
/// The post-graft apply.
pub(crate) const RELAY_APPLY_MS: u64 = 170;
/// The measured wire size of a real block (median `[wire-roundtrip]` frame on real nodes; history and the distribution in
/// `dag.rs` beside the re-export). ⭐ A-F84 (speed5, 2026-11-17): the MEASURED median of main 7d357574's real-node frames
/// (525 frames, the verifier's three-node rig, dag.rs), taken into the target once the crowd start-up stall is fixed (AIMD
/// pacing, `node_runtime::next_pace_milli`) and `pace` passes at it. FORMAT: the mesh's derived target 3,221 → 1,953 ms.
pub(crate) const RELAY_BLOCK_BYTES: u64 = 390_544;
/// The block lane's parts (`block_part`) and one lane's measured rate.
pub(crate) const RELAY_LANES: u64 = 4;
pub(crate) const RELAY_LANE_BYTES_PER_MS: u64 = 100;

/// Two relay rounds of a whole block: legs + bytes / lane rate + apply, twice.
pub const PRODUCTION_RELAY_FLOOR_MS: u64 =
    2 * (RELAY_ROUND_LEGS_MS + RELAY_BLOCK_BYTES / (RELAY_LANES * RELAY_LANE_BYTES_PER_MS) + RELAY_APPLY_MS);

/// The mesh's block-rate target: half of a node's reference intake spent on frames,
/// `⌈ RELAY_BLOCK_BYTES / (½ × RELAY_LANES × RELAY_LANE_BYTES_PER_MS) ⌉`.
pub const MESH_TARGET_SPACING_MS: u64 = (2 * RELAY_BLOCK_BYTES).div_ceil(RELAY_LANES * RELAY_LANE_BYTES_PER_MS);
