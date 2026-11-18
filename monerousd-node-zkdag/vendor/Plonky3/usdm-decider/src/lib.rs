// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! MoneroUSD phone-class light decider (#135): the HVZK-WHIR hiding entries + the rec-block
//! witness adapter, in the decider's KoalaBear field.
//!
//! This crate is deliberately SMALL and depends ONLY on the `p3-whir` / `p3-sumcheck` /
//! KoalaBear primitives — NEVER the pqpool `circuit.rs` monolith (a single ~68k-line file whose
//! rustc compile costs multiple GB of RAM). So building/testing the light decider is a fast,
//! constant, small-RAM compile — honoring the no-monolithic-path / no-blow-up-on-any-axis pillar
//! for the DEV loop too, not just the proof. The pqpool crate depends on THIS crate for the
//! rec-block routing (`pqspend_rec_block_prove`), never the reverse.

// ⭐ DB-371 (lane stable 2026-11-02) — THE TEST BINARY RUNS THE NODE'S ALLOCATOR. The node binary declares jemalloc with a 1 s
// dirty decay (usdmd-node `main.rs`, DB-92); this crate's tests ran the platform allocator, whose cached large frees stay
// charged to the process (MEASURED, release-shape certificate profile: `vmmap` MALLOC_LARGE (empty) 4.4 GB, all compressed,
// none live), so the prover-memory profile pin read a footprint no node holds. Test-only: the release crate declares nothing.
#[cfg(all(test, not(target_env = "msvc")))]
#[global_allocator]
static TEST_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
#[cfg(all(test, not(target_env = "msvc")))]
#[allow(non_upper_case_globals)]
#[export_name = "_rjem_malloc_conf"]
pub static malloc_conf: &[u8] = b"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0,narenas:4\0";

pub mod merkle_path_air; // §BD-2(c): a Merkle authentication path as CONSTRAINTS — the in-circuit opening core
pub mod opening_auth_air; // §BD-2(c): leaf sponge + path in ONE table — the tie is row-local
pub mod c4_openings; // SPEED C4 step 1: a payment carrier's WHIR openings, authenticated in-circuit (opening_auth tables)
pub mod stir_group_air; // SPEED C4 V4+V5: one WHIR query group — leaves, paths, folds and the γ combine — in one table
pub mod settlement_delta; // §BA/§BB: the bound note-transition aggregate
pub mod member_ledger; // §RF-3 §12: the padded member ledger — member rows at LEDGER_ROWS, anchors looked up in the ring
pub mod tree_ledger; // V2 piece 2: the note ledger for a block in tree form — the ledger's laws, no bound step
pub mod tag_ledger; // §18 (padding spec): the pair-row class's tag table — a spend's 32 tags on 16 hidden rows, chained on a tied bus
pub mod member_ring; // §RF-3 §12.2: the member ledger's anchor lookup in the public ring (LogUp, every bus row tied)
pub mod member_path_gate; // DB-223: the member-path class — a block proves every spend input exists under an anchor it names
pub mod committed_weld; // §BD-2: the bound step, the transcript sponge and their cross-ties in ONE proof
pub mod recursion_bound; // §BD-2(b): the outer AIR evaluates the INNER constraint on the opened row
pub mod committed_air; // §BD: an AIR carrier whose opened values are BOUND to a trace commitment
pub mod hiding_decider;
pub mod light_commit; // DB-452: the light decider's openings, bound to a WHIR commitment
pub mod gpu_grind; // SPEED G1: the proof-of-work grind on the GPU (Apple Metal), every witness checked on the CPU
pub mod background_prove;
pub mod light_batch_merge; // R4 lever 4: several light-decider statements proved as ONE batch (one WHIR pair, not three)
pub mod whir_rec_block;
pub mod nullifier_insert_air;
pub mod nf_sparse_air;
pub mod nf_compact_air; // DB-453: the compact shard nullifier tree — the band step at 64 rows per insert
/// DB-353 shape (2): the aggregate-ready keyed shard sub-carrier (one contiguous shifted run, cell publics, live count).
pub mod nf_band_air;
/// Padding spec v2 §2/§2.6 (2026-09-30): the SLOT LEDGER ROW — hidden row classes, cover laws over the header seed, the
/// seed commit, justified cells and the device-slot claim; the constant-length list that closes the spend-count leak.
pub mod slot_ledger;
/// K1 (2026-09-30): the PROVER SOURCE FINGERPRINT the test-time proof caches key on — test support only.
#[cfg(any(test, feature = "test-support"))]
pub mod prover_fingerprint;
// `anchor_set_membership` (membership as a SET question over a LogUp bus, folded K steps into one proof) was DELETED
// 2026-09-29: zero node/wallet users, superseded by `member_path_gate` (DB-223), and its fold recursed over a two-phase
// bus object that the fixed-degree rows cannot carry (record in whir_rec_block.rs above `lay_vals_row`). Backup:
// anchor_set_membership.rs.preDelete-20260929.
pub mod note_membership_air; // O(1) note membership by recursive fold — the twin of nf_sparse_air's absence carrier
pub mod split_ladder_air; // the SPLIT LADDER: a note is debited per state, so only the paid fraction moves
pub mod confidential_solvency;
pub mod solvency_arith; // the peg's exact solvency relation + u256 limb arithmetic, Kani-proven (kani-proofs)
/// ⛔ THE CONSTRAINT MANIFEST — which value-carrying trace columns are RANGE-BOUND and which are raw
/// field elements. The class no node-side oracle can reach: a circuit that accepts a forged witness is
/// one whose nodes all AGREE. Ratchets the unbound count downward.
pub mod constraint_manifest;
pub mod limb_gadgets; // 8-bit-limb arithmetic + in-circuit ≥ gadgets (survives the retired pool-AMM curve AIR)
// #135 keystone: the generic multilinear AIR→sumcheck zerocheck (production promotion of the
// proven A4.5.1 composed-AIR reduction) — the constraint-verify layer that replaces the ~11s FRI
// rec prove. The rec-block AIRs drive their constraints through `prove/verify_air_zerocheck`.
pub mod air_zerocheck;
/// ⭐ Test-only FREE-CELL CENSUS: which cells of an honest trace does its constraint leave free? Hooked in
/// `prove_air_zerocheck`, env-gated by `FREE_CELL_CENSUS`. See the module doc.
#[cfg(test)]
pub(crate) mod free_cell_census;
pub(crate) mod mutation_census;
#[cfg(test)]
pub(crate) mod rank_census;
pub mod note_member_row;
pub mod br15_audit;
pub mod spartan_ccs;
pub mod spartan_gadgets;
pub mod uniform_r1cs;
pub mod universal_row;
pub mod verifier_program;
pub mod matrix_argument;
pub mod fixed_program;
pub mod acc_program; // M5: the certificate's acc-step rows — fold, limb-wise work, the state hash, the genesis program
pub mod certificate_door; // M6: the certificate door — one Spartan-committed proof of the universal row per step (prove/verify)
pub mod matrix_program;
pub mod spartan_program;
pub mod whir_program;
pub mod whir_weights;
#[cfg(test)]
mod transcript_census;
// THE canonical whole-chain adopt-gate decider (#29 DSYNC): ONE prove/verify implementation every
// build flavor links (daemon FFI + pure-Rust phone), so cross-implementation DSYNC can never drift.
pub mod whole_chain;
pub(crate) mod tape_program; // SPEED R8: the compiled tape's register program (whole_chain::CompiledTape evaluates through it)
pub mod whole_chain_cert; // #29 join door: the recursive fold-from-genesis certificate (Mina shape, our WHIR crypto)
#[cfg(test)]
mod poseidon2_air_parity; // the in-circuit challenger permutation must equal the live one, or no IVC
pub mod sponge_chain_air; // the sponge as CONSTRAINTS: capacity carry + rate overwrite make rows one sponge
pub mod acc_step_air;
pub mod perm_row; // lane d 2026-10-27: the ONE safe Poseidon2 row generator (no MaybeUninit reinterpretation)
pub mod pow_pq_air;
pub mod work_target_air; // the PoW target as constraints: a digest becomes PROVEN work // the PoUW hash as constraints: the miner PROVES its work, once per found block // the IVC accumulator recurrence + genesis anchor + accumulated work
pub mod transcript_bind_air; // welds the constrained sponge's squeezed cells to a consumer's committed ones

// Crate-root re-export of the two production call-site entries the pqpool circuit.rs rec-block
// routing (prove side, in `pqspend_rec_block_prove`) and the node (verify side) invoke — so the
// wiring imports a clean path: `usdm_decider::prove_rec_block_light_decider_bytes` /
// `usdm_decider::verify_rec_block_light_decider_bytes`. These are the ONLY two functions the
// circuit.rs call-site swap needs; everything they call is built + proven inside this crate.
pub use whir_rec_block::{
    build_acc_bus_tied, build_leaf_bus_full_tied, prove_rec_block_light_decider_bytes,
    prove_rec_block_light_decider_bytes_with_bus, prove_rec_block_light_decider_selfcontained_bytes,
    verify_rec_block_light_decider_bytes, verify_rec_block_light_decider_selfcontained_bytes,
    // #29 DSYNC PRODUCE (serve side): the zero-input canonical whole-chain light-decider anchor a joining node
    // verifies once, then O(1)-adopts the served frontier snapshot. The node's `decider_prove_light` calls this.
    prove_canonical_rec_block_decider_bytes,
    // #135 Mina-fast DIRECT (row-local) broadcast prover — the engine Send/Swap/token-create/… ride.
    AirDirectBundle, prove_air_direct_light_decider_bytes, verify_air_direct_light_decider_bytes,
    // Self-contained (pinned-param + public-IO-bound) direct entries the pqpool wrappers + node call.
    prove_air_direct_light_decider_selfcontained_bytes, verify_air_direct_light_decider_selfcontained_bytes,
    // #135 MULTI-AIR plain batch — the bound engine with no bus (DB-452): the whole-chain decider, the band slice.
    prove_air_batch_light_decider_selfcontained_bytes, verify_air_batch_light_decider_selfcontained_bytes,
    // #135 BUS-AWARE batch engine + source cross-tie — the VALIDATOR FINALITY CERT retirement (5 LogUp buses).
    AirBatchBusBundle, CrossTieSpec, PUBLIC_BIND_TABLE, build_cert_bus_tied, build_finality_weight_bus_tied,
    prove_air_batch_light_decider_bytes_with_bus, verify_air_batch_light_decider_bytes_with_bus,
    prove_air_batch_light_decider_selfcontained_bytes_with_bus,
    verify_air_batch_light_decider_selfcontained_bytes_with_bus,
    // SHARED SPEND-CARRIER ENTRY (user-approved 2026-07-10): the ONE config-pinned spend
    // prove+verify the V2 wallet AND the node both call — sound-by-construction single source.
    // The 3 PqSpendAir gates: conservation (no-inflation), nullifier (nf=Poseidon(sk,leaf)),
    // and in-circuit Poseidon-Merkle frontier membership (note-on-chain).
    SpendRow, SpendConservationGate, SPEND_CARRIER_DOMAIN, spend_carrier_cols, SC_WIDTH, SC_IN, SC_OUT, SC_FEE,
    // THE note commitment — one formula, defined once (2026-09-11): value as limbs, tag+key in the inner round.
    asset_note_cm, note_value_lanes, note_inner_key, USDM_ASSET_TAG,
    prove_spend_carrier_bytes, verify_spend_carrier_bytes,
    SpendMainRow, SpendMainGate, prove_spend_main_carrier_bytes, verify_spend_main_carrier_bytes,
    MembershipWitness, SpendMembershipGate, SPEND_MEMBERSHIP_DOMAIN,
    prove_membership_carrier_bytes, verify_membership_carrier_bytes,
    // The UNIFIED full PqSpendAir row (conservation + note-opening + nullifier + membership, cross-bound).
    SpendValidityWitness, SpendValidityGate, SPEND_VALIDITY_DOMAIN,
     verify_spend_validity_carrier_bytes,
    // THE VAULT (docs/GOODS-AND-SERVICES-LAYER-SPEC-20261109.md §9.1): the note-class spend's one prover and verifier,
    // under the verifier's chain clock, and a vault note's condition, commitment and secret hash.
    prove_note_spend_bytes, verify_note_spend_bytes, note_spend_public_bind, note_spend_row_width,
    NoteSpendExtras, VaultBranch, VaultLock, VaultNote, VaultOpen, VaultSecret, vault_lock, chain_hours, CHAIN_HOUR_MS, NO_LOCK,
    PaymentStatement, pay_verifier_key, payment_note_cm, prove_payment, public_verifier_key, simulate_payment, verify_payment,
    // MINT/COINBASE — a carrier that creates value with NO INPUT NOTE, so it has no membership to prove
    // and therefore no root and no depth. Replaces the deleted mint wrappers that borrowed the bond gate.
    MintValidityGate, MINT_VALIDITY_DOMAIN, prove_mint_validity_bytes, verify_mint_validity_bytes,
    // DB-365 (yield): the reward note opens to the public reward under a key derived from the principal's.
    RewardFollowsPrincipalGate, REWARD_FOLLOWS_DOMAIN, reward_spend_key, prove_reward_follows_principal_bytes,
    verify_reward_follows_principal_bytes,
    // The cross-bound variant: proves `Poseidon(spent_leaf, nullifier) == leaf_commit` so a spend and a
    // note-membership carrier presented together are provably about ONE note.
    prove_spend_validity_carrier_with_commit_bytes,
    // The FULLY-PRIVATE MULTI-INPUT variant: ONE tx spending N confidential inputs → 2 outputs, conservation
    // `Σ value_in == value_out + fee` proven in-circuit (amounts private), N public nullifiers, one recipient note.
    MultiSpendInput, MultiSpendValidityWitness, MultiSpendValidityGate, MULTI_SPEND_VALIDITY_DOMAIN,
    prove_multi_spend_validity_carrier_bytes, verify_multi_spend_validity_carrier_bytes,
    // The VALIDATOR-BOND variant: the full row PLUS a public `out0_value == bond_amount` weld (public bond
    // weight welded to the value actually locked — no over-claim, no bonded-note key reveal).
    BOND_VALIDITY_DOMAIN, 
    prove_bond_validity_carrier_with_commit_bytes, 
    verify_bond_validity_carrier_with_commit_bytes,
    // The MINT-VALIDITY variant: a depth-1 vacuous-membership row that welds `out0_value == value` — so the node
    // can credit a node-computed, backed reward (stake-to-earn payout / PSM mint) as a confidential note the wallet
    // CANNOT inflate, with NO KEM key on the node. Same weld as a bond, no real input spent.
    // #73/#142 COINBASE POW-BIND on the WHIR light decider: mint-shaped sk-opening proof with the per-block
    // challenge `c` bound into the transcript (non-outsourceable). Retires the FRI/STARK pow-bind pi.
    // The Poseidon frontier parent-hash the wallet builds its note copath with (matches the gate).
    poseidon_pair,
};

// WHIR-PCS research prototypes (A4 family) — test-only, relocated out of the pqpool circuit.rs
// monolith (2026-07-07) so they no longer bloat pqpool's cargo-test compilation unit.
#[cfg(test)]
mod whir_pcs_research;

// PQ-STARK foundational-primitive research (range proof / Merkle membership / nullifier /
// rotation / note-commitment / spend-auth / PQ-sigs / supply-solvency) — test-only, likewise
// relocated out of circuit.rs (2026-07-07). External-only (p3_field + p3_koala_bear).
#[cfg(test)]
mod pq_stark_research;

// DeFi / network-privacy STARK foundations (network privacy / bridge / dark-contract / L2 /
// mempool privacy / confidential AMM / governance / confidential lending) — test-only, relocated
// out of circuit.rs (2026-07-07). External-only (p3_field + p3_koala_bear).
#[cfg(test)]
mod defi_foundations_research;

// Is the sparse tree 1-round fold second-preimage resistant? Measured, not assumed.
mod sparse_fold_preimage_probe;

// DB-213c: what each production verifier accepts from a prover holding NO witness — the forgery census.
#[cfg(test)]
mod db213_forgery_census;

// The chain compression function: one Poseidon2 permutation, truncated. Replaces the invertible 1-round fold.
pub mod postcommit_bus; // DB-159: the LogUp bus challenge drawn AFTER the trace is committed
pub mod dsol_vm;
pub mod dsol_blob_air; // D4: a call's storage blob, proven to rebuild its post-state, encrypted under the deployed key
pub mod dsol_asm; // the DSOL assembler: how a site's author writes the back end they host on the chain
pub mod dsol_cpu_air; // the DSOL machine AS CONSTRAINTS — arbitrary contract execution, proven // the DSOL machine: ONE execution semantics, beside the circuit that constrains it
pub mod poseidon2_compress;

// The sparse insert over a REAL permutation, naming the key it consumes (replaces the invertible 1-round gate).
pub mod sparse_fold_air;
pub mod agg_mode; // lane agg: the carrier doors' Record / Core modes and the block's openings tables (docs/LEVEL-AGGREGATE-SPEC-20261115.md §10)
pub mod gate_trace; // lane agg, the tree, step 1: a carrier gate as a straight-line program (docs/LEVEL-AGGREGATE-SPEC-20261115.md §12)
mod agg_probe; // lane agg: the level aggregate's measurement probes (test-only, #[ignore]; docs/LEVEL-AGGREGATE-SPEC-20261115.md §6)
