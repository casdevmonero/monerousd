// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! # usdmd-node — the MonerousD greenfield node
//!
//! A ground-up node in the shape MonerousD actually is: **ZK + PoUW + GHOSTDAG-DAG**, PQ base
//! layer, libp2p onion "iron mesh" transport. It reuses the crown-jewel Rust crates we already
//! own — `usdm-decider` (the pure-Rust WHIR light decider) and the arti onion mesh (the
//! onion gossip mesh) — and leaves the Monero C++ `cryptonote_core`/levin daemon behind. That
//! monolith's linear-chain / levin / full-history / ring-sig assumptions were the source of the
//! drift that this project kept fighting (validium can't produce, gossip won't graft, single
//! producer). Built in the right shape, the pillars hold *by construction*:
//!
//! * **Every node produces + gossips** — a producer builds the next block from the tips it
//!   already holds ([`dag::Dag::tips`]); it never refetches parent blocks, so a validium /
//!   instant-synced node is a first-class producer. No single-producer, no halts.
//! * **Instant sync** — a joining/restarting node adopts one constant-size decider proof
//!   (#29 DSYNC) + the persisted frontier (#106); it never downloads block history.
//! * **100% private + PQ + sound** — all header roots are commitments (no raw witness); value
//!   lives in ZK confidential notes; consensus validity is a recursive WHIR verify.
//!
//! ## Modules (all real, compiling, tested — `cargo test`; `cargo run` boots a node that advances)
//! * **Consensus spine** — [`hash`] · [`block`] · [`dag`] (the GHOSTDAG store) · [`ghostdag`]
//!   (mergeset k-cluster coloring + true blue-score) · [`mempool`] (PQ tx pool + #72 anti-spam
//!   stamp) · [`miner`] (adaptive DAA, never pinned) · [`relay`] (consensus-strict graft) ·
//!   [`params`] (governance-tunable `ChainParams`) · [`consensus`] (validity gates).
//! * **Overlays** — [`validator`] (PoS bond + finality tracker) · [`governance`] (bicameral runtime
//!   retune) · [`site`] + [`merkle`] (uncensorable node-served sovereign sites + WASM) · [`pqauth`]
//!   (fail-closed PQ-signature seam) · [`rpc`] (loopback control) · [`node`] (assembles them all).
//! * **Network privacy** (fixed, 100% by default) — [`net`] (onion-only; IPs unrepresentable) ·
//!   [`mix`] (Sphinx multi-hop) · [`da`] (data-availability sampling).
//!
//! Real post-quantum crypto is wired (via `pqcrypto-mldsa` / `pqcrypto-mlkem`): **ML-DSA-65** sign +
//! verify ([`pqauth`], the verifier pinned in the node — it authenticates finality votes + site
//! publishes, and drives `finalized_height` past 0 in the bring-up), and **ML-KEM-768** key
//! establishment for every onion-mix hop ([`mix`]).
//!
//! The **O(1) whole-chain decider ZK-verify + no-inflation gate** ([`decider`]) is the block-decider
//! anchor a joining / validium node checks to instant-sync. Its seam is fail-closed by default
//! ([`decider::UnverifiedDecider`] rejects every bundle); the REAL verifier is the pure-Rust
//! HVZK-WHIR light decider in the small vendored `usdm-decider` crate ([`whir_decider::WhirDecider`]) —
//! the ONE canonical construction every device runs (desktop daemon, wallet in-process, iPhone), so any
//! node's proof verifies on any other. Per-tx user actions — Send / bond / Swap / … — ride the same
//! engine's direct spend gate (`whir_decider::pqspend_direct_verify_carrier`). The retired pqpool
//! STARK-era FFI is DELETED (never linked); the build loop stays fast because `usdm-decider` depends only
//! on the small p3-whir/p3-sumcheck crates. On top of it, [`sync`] is the #29 DSYNC / #106 frontier
//! instant-sync adopt path: a joining node verifies ONE decider bundle + binds the persisted frontier and
//! jumps to tip in O(1) (no block-by-block replay) — becoming a first-class producer immediately.

/// BLE MTU cell framing — fragment/reassemble a [`net::CELL_SIZE`] cell across BLE-notification-sized
/// GATT writes, so the desktop and iPhone nodes converge over a real Bluetooth link (both frame IDENTICALLY
/// from this shared module). Pairs with [`transport::BridgeCellTransport`] (the externally-pumped cell pipe).
pub mod ble_frame;
pub use usdm_ledger::block;
pub mod block_window;
pub use usdm_ledger::consensus;
pub mod dag {
    pub use usdm_ledger::dag::*;
    #[cfg(all(test, feature = "pins-core"))]
    mod selected_tip_ancestry_is_o1_tests;
    #[cfg(all(test, feature = "pins-core"))]
    mod af37_af40_finality_pins;
}
pub use usdm_ledger::fixed;
pub mod ghostdag {
    pub use usdm_ledger::ghostdag::*;
    #[cfg(all(test, feature = "pins-core"))]
    pub(crate) mod canonical_merge_order_tests;
}
pub use usdm_ledger::hash;
/// ⭐⭐⭐ §BA/§BB — the block's NOTE TRANSITION as evidence a peer can check holding no transaction
/// body: one bound aggregate plus the tuple list it stands over, and an ALLOW-list built from that list.
pub mod note_transition {
    pub use usdm_ledger::note_transition::*;
    #[cfg(test)]
    #[path = "node_tests.rs"]
    mod tests;
}
/// ⭐⭐⭐ DB-223 — the block's MEMBERSHIP TRANSITION: one aggregate over the spends' member-path carriers, proving every
/// spend input is a leaf under an anchor the door checks against its own ring, naming no record.
pub use usdm_ledger::member_transition;
pub use usdm_ledger::verify_cache; // a block's transition proofs verify once per node (Bitcoin's script-execution cache)
pub mod spend_evidence; // §22c: every node verifies every spend a block states, itself (Bitcoin's ConnectBlock)
pub mod agg_root; // the level aggregate, milestone 2: the node's one seam to the proof tree (a peer holds statements + one root a block)
/// ⭐ DB-223 — the WALLET's member witness book: a depth-64 path per owned note, captured at arrival and kept current
/// from the public path-refresh stream, and the member-path carrier a spend attaches (one spelling for wallet + pins).
pub mod member_witness;
pub use usdm_ledger::window_index;
pub use usdm_ledger::mempool;
pub use usdm_ledger::miner;
pub use usdm_ledger::net;
/// The REAL Tor `.onion` libp2p `CellTransport`, linked over the C `libp2p_ffi` mesh. Compiled ONLY under
/// `libp2p-onion-ffi` (the prebuilt macOS/Linux cdylib), since a pure-Rust / `aarch64-apple-ios` build cannot
/// link that C mesh — there, the in-process node peers over the wallet's embedded arti Tor (same onion-only
/// privacy, no C dylib, no IP leak). Onion-only is preserved on BOTH paths; only the transport *impl* differs.
#[cfg(feature = "libp2p-onion-ffi")]
pub mod onion_transport;
pub use usdm_ledger::params;
pub use usdm_ledger::relay;
pub mod transport;
// PURE-RUST Tor v3 .onion mesh transport (arti) — the iOS-safe, C-dylib-free CellTransport so a phone/desktop
// node JOINS THE REAL MESH (no loopback island). Enabled by the `arti-onion` feature.
pub mod account_da {
    pub use usdm_ledger::account_da::*;
    #[cfg(all(test, feature = "pins-core"))]
    #[path = "node_tests.rs"]
    mod tests;
}
pub use usdm_ledger::address;
/// THE DECODE DOORS (B1 (ii), 2026-10-22): every production decoder of outside bytes, callable by name — what the
/// cargo-fuzz targets (`fuzz/`) and the in-process replay pin push hostile bytes through.
pub mod decode_doors;
#[cfg(feature = "arti-onion")]
pub mod arti_transport;
/// MonerousD's own post-quantum mix layer: a separate anonymous transport that replaces Tor while Tor is down.
#[cfg(feature = "arti-onion")]
pub mod pqmix;
/// Buy-USDm atomic-swap BRIDGE: real threshold-custodied taproot deposit address (secp256k1, bridge
/// endpoint) + the sound PQ t-of-n threshold mint (`authorize_mint`) the whole swap is proven against.
pub use usdm_ledger::bridge;
pub use usdm_ledger::bridge_assets; // THE ONE TABLE OF BRIDGE COINS: every door, route, wallet and app reads which coins the bridge holds from here
/// REAL Bitcoin deposit watcher (bridge endpoint): each validator independently reads the external chain's
/// confirmed-balance data for the reserve address, so USDm mints ONLY after a real on-chain deposit confirms.
pub use usdm_ledger::btc_watch;
pub use usdm_ledger::btc_tx; // DB-121 — the Bitcoin exit leg: k-of-n OP_CHECKSIGADD custody script, taproot output, BIP-341 sighash, witness
pub mod btc_payout; // DB-121 — the Bitcoin payout lane: proposals, independent custodian signatures, broadcast, observed settlement
#[cfg(any(test, feature = "bridge-test-oracle"))]
pub use usdm_ledger::btc_sim; // §NETSIM-LAUNCH — the SIMULATED Bitcoin (Core regtest semantics on the sim clock) every bridge flow runs against in netsim
#[cfg(any(test, feature = "bridge-test-oracle"))]
pub mod xmr_sim; // §NETSIM-LAUNCH — the SIMULATED Monero (k-of-n custody wallets, 10-block lock, reorgs on the sim clock) behind xmr_rpc's Sim arm
#[cfg(any(test, feature = "bridge-test-oracle"))]
pub mod btc_regtest; // DB-121 — a real Bitcoin Core (regtest) a test raises to judge both external legs; absent from a release daemon
#[cfg(any(test, feature = "bridge-test-oracle"))]
pub use usdm_ledger::test_ports; // 2026-10-27 — per-instance loopback port blocks for the external processes a test raises (Bitcoin Core test_framework shape)
pub mod eth_rpc; // THE CUSTODIAN'S OWN ETHEREUM SOURCE over JSON-RPC (this machine or a .onion): finalized reads and raw sends (external-chain endpoint)
pub mod xmr_rpc; // DB-121x — the custodian's own monero-wallet-rpc / monerod over JSON-RPC (external-chain endpoint)
pub mod xmr_custody; // DB-121x — the bonded set's k-of-n Monero multisig wallet, formed over the mesh; the address any node serves
pub mod xmr_payout; // DB-121x — the Monero payout lane: sync, proposal, sequential signatures, submit, observed settlement
pub mod xmr_sweep; // SAFE AT SCALE stage three (A-F20) — a replaced custody key's Monero wallet is swept to the vault's current key
#[cfg(any(test, feature = "bridge-test-oracle"))]
pub mod xmr_regtest; // DB-121x — a real Monero daemon (regtest) plus per-custodian wallet-rpcs a test raises; absent from a release daemon
pub use usdm_ledger::clue_registry;
pub mod cover {
    pub use usdm_ledger::cover::*;
    #[cfg(all(test, feature = "pins-core"))]
    #[path = "node_tests.rs"]
    mod tests;
}
pub use usdm_ledger::da;
#[cfg(all(test, feature = "pins-core"))]
mod da_seed_regen_tests; // a restart must not forget a seed-only record (live-pair NOT_READY 2026-09-02)
mod copath_want_registration_tests; // DB-227: a want must name a record the node can place (gate I, 2026-09-26)
#[cfg(all(test, feature = "pins-core"))]
mod db350_cm_ask_privacy_tests; // DB-350: no ask a node sends names a commitment its wallet owns
#[cfg(all(test, feature = "pins-core"))]
mod db354_producer_record_parity_tests; // DB-354: a producer records exactly what its peers record
#[cfg(all(test, feature = "pins-core"))]
mod db356_bucket_ask_order_tests; // DB-356: the account-bucket ask's slots carry no order
pub use usdm_ledger::oscall; // lane d 2026-10-27: every OS call through a safe wrapper crate — no `unsafe` in the shipping tree
pub use usdm_ledger::log_cap; // a node bounds its own stderr on disk (2026-09-03: unbounded launchd logs)
pub use usdm_ledger::budget_clock; // PERF TIER step 1: per-tick work budgets read wall time on a daemon, CPU time on a simulated node
pub use usdm_ledger::local_origin; // DB-374: the local HTTP servers answer only the user's own software (Host / Origin / Sec-Fetch-Site)
#[cfg(test)] // test/audit suite: it must not ship inside the production node binary
mod store_bound_manifest_tests; // every store declares its bound (2026-09-03 blowup)
mod peg_o1_replay_tests;
// Does the live accumulator accept a SOLVED non-membership copath? Measured against the real verifier.
mod sparse_fold_forgery_pin;
mod canonical_ordinal_after_resume_tests; // the restart seam of the record ordinal (gates 32–37)
mod orphaned_prerestart_records_tests; // the restart wall: records the network never saw (gates 32–37)
#[cfg(all(test, feature = "pins-core"))]
mod small_scope_model_tests; // §PROOFS step 2: exhaustive small-scope checks of GHOSTDAG order, the nf door, first-spender-wins
mod canonical_record_fold_tests; // v31: records fold in DAG order at depth — identical ordinals on every node
#[cfg(all(test, feature = "pins-harness"))]
mod fold_schedule_fuzz_tests; // the SEARCH: random produce/deliver/restart/jump schedules vs one property
#[cfg(test)]
mod consensus_scenarios; // cases as DATA: every class a gate run found, replayable in seconds
#[cfg(test)]
mod consensus_corpus; // the FROZEN-CONSENSUS corpus: Bitcoin's IBD replay made explicit for an O(1)-jump node
#[cfg(all(test, feature = "pins-core"))]
mod depth_parity;
#[cfg(test)]
mod dex_cross_party_scenarios; // the DEX has never traded between two parties — this asks whether it can
#[cfg(all(test, feature = "pins-core"))]
mod mature_chain_invariants; // the rules decades-old chains enforce, as checks against our code
#[cfg(test)]
#[cfg(all(test, feature = "pins-harness"))]
mod mesh_schedule_search_tests; // the FULL-ALPHABET search: every layer, every property, the adversary too
#[cfg(all(test, feature = "pins-harness"))]
mod mesh_runtime_scenarios; // the RUNTIME-MESH backend: the same cases through real NodeRuntimes over an in-memory cell hub
mod idle_record_regeneration_tests; // an idle record is regenerated, never fetched or kept (gate 40)
#[cfg(all(test, feature = "pins-core"))]
mod family_d_door_audit_tests; // §9.6 FAMILY D: the certified-bundle / snapshot / overlay / oracle doors
#[cfg(all(test, feature = "pins-core"))]
mod block_ingress_door_audit_tests; // FAMILY A door audit (§9.6 six questions) — the siblings of the 2026-09-07 descent-door PoW omission
mod block_wire_budget_tests; // what a block costs on the wire, field by field — the follower's bandwidth budget (gate J, 2026-09-26)
#[cfg(all(test, feature = "pins-core"))]
mod lane1_adversarial_review_tests; // ADVERSARIAL REVIEW of the 2026-09-07 hole-A3/A4 closure — fresh attacks, not the fixer's pins
#[cfg(all(test, feature = "pins-core"))]
mod lane_b_body_binding_tests; // LANE B: the honest side of the 2026-09-08 body-binding closure + the class the fix itself makes possible
#[cfg(test)] pub(crate) mod test_census; // the three harness recorders production #[cfg(test)] hooks call — always on for tests
#[cfg(all(test, feature = "pins-harness"))] mod harness; // THE ADVERSARIAL HARNESS — lane F (stateful invariant fuzz) + lane C (circuit soundness)
#[cfg(all(test, feature = "pins-harness"))] mod rogue_role_pins; // ROGUE-ROLE CENSUS cells (lane-harness): one pin per class × attack, judged on a PEER
pub use usdm_ledger::decider;
pub use usdm_ledger::directory;
/// DSOL v2 — the node's post-quantum, 100%-private smart-contract layer (the language custom tokens,
/// NFTs, AMM pools, and wrapped coins are written in). PQ at every layer by construction; proven, not
/// asserted, via `dsol::dsol_layer_manifest`.
pub use usdm_ledger::dsol;
pub use usdm_ledger::faucet;
pub use usdm_ledger::governance;
pub use usdm_ledger::letter;
pub use usdm_ledger::liquidation; // THE COLLATERAL LIQUIDATION LANE — the aggregate-ratio invariant + the crash simulation
pub use usdm_ledger::decoy_tx; // §BR-8 B8-a: conditional decoys — the batch booking and the return
pub use usdm_ledger::debt_units; // §BR-4/§BR-7: borrowing against Bitcoin as standard debt units (public cell counts, band epochs)
pub use usdm_ledger::unit_open_tx; // §BR-4 B4-2: one debt unit opened against one co-signed Bitcoin deposit (Class::UnitOpen)
pub use usdm_ledger::unit_close_tx; // §BR-4 B4-3: one debt unit closed — debt burned, collateral returned in payout pieces (Class::UnitClose)
pub use usdm_ledger::pot_fill_tx; // §BR-3 17.5 layer 1: the repayment pot sold at the floor, its proceeds retired by custody
pub use usdm_ledger::theft_repayment_tx; // §BR-3 17.5: a custody theft repaid in layers (pot, buffer, pool, haircut) as a chain object
pub use usdm_ledger::liquidation_tx; // A LIQUIDATION IS A CHAIN OBJECT — the block-carried form of a collateral re-mark
pub mod wrapped_asset_tx { // A WRAPPED-ASSET REGISTRATION IS A CHAIN OBJECT — the ratio rides a block, not a socket
    pub use usdm_ledger::wrapped_asset_tx::*;
    #[cfg(all(test, feature = "pins-core"))]
    #[path = "node_tests.rs"]
    mod tests;
}
pub use usdm_ledger::wrapped_mint_tx; // A WRAPPED MINT IS A CHAIN OBJECT — the note AND the peg transition, on one object
#[cfg(test)]
mod chain_action_manifest_tests; // ECOSYSTEM SWEEP: a handler may not perform a transition no block carries
#[cfg(all(test, feature = "pins-harness"))]
mod chain_action_carriage_tests; // RUNTIME HALF: what a route publishes must carry the WHOLE transition
#[cfg(all(test, feature = "pins-core"))]
mod digest_width_gate; // §AG CLASS 9: every bytes↔digest helper is total and full-width at the live lane count
pub use usdm_ledger::order_book; // resting orders in DA/gossip — the DEX book, never consensus state
pub use usdm_ledger::order_fill_tx; // A FILL IS A TRANSACTION — the on-chain form of a DEX trade
pub use usdm_ledger::chain_object; // WHAT THE MEMPOOL MAY CARRY — one place naming every consensus object class
pub mod asset_tx { // AN ASSET IS A CHAIN OBJECT: token/NFT creation and supply mint as transactions
    pub use usdm_ledger::asset_tx::*;
    #[cfg(test)]
    #[path = "node_tests.rs"]
    mod tests;
}
pub use usdm_ledger::contract_state; // §BR-12 L1: the ONE contract-state root (a depth-256 Poseidon2 sparse map, the node holds the root alone)
pub mod dsol_deploy_tx { // §BR-12 L1: a DSOL contract deploy is a chain object applied at the fold (Class::DsolDeploy, byte 19)
    pub use usdm_ledger::dsol_deploy_tx::*;
    #[cfg(all(test, feature = "pins-core"))]
    #[path = "node_tests.rs"]
    mod tests;
    #[cfg(test)]
    #[path = "fixtures_node_tests.rs"]
    pub(crate) mod fixtures;
}
pub use usdm_ledger::dir_entry_tx; // audit F15: a directory entry reaches the chain only as an object that pays for its bytes (Class::DirEntry, byte 53)
pub mod dsol_call_tx { // §BR-12 L2: a proven DSOL contract call is a chain object applied at the fold (Class::DsolCall, byte 18)
    pub use usdm_ledger::dsol_call_tx::*;
    /// ⭐ §BR-12 F13 — THE TRANSITION RING: after a deploy and a call, each node's ring holds the two transitions in order, chained
    /// `pre → post`, and a follower that starts from the EMPTY tree and walks them lands on the node's root. Asserted on both nodes
    /// (the peer applied from the block alone); a follower standing on an unrelated root applies nothing (no abandoned-branch
    /// entry can move it).
    #[cfg(all(test, feature = "pins-core"))]
    mod ring_tests;
    #[cfg(all(test, feature = "pins-core"))]
    #[path = "node_tests.rs"]
    mod tests;
    #[cfg(test)]
    #[path = "fixtures_node_tests.rs"]
    pub(crate) mod fixtures;
}
pub mod dsol_fee_update_tx { // §BR-12 L3: the deployer's tighten-only publisher-fee update (Class::DsolFeeUpdate, byte 37)
    pub use usdm_ledger::dsol_fee_update_tx::*;
    #[cfg(all(test, feature = "pins-core"))]
    #[path = "node_tests.rs"]
    mod tests;
    #[cfg(test)]
    #[path = "fixtures_node_tests.rs"]
    pub(crate) mod fixtures;
}
pub mod bridge_credit_tx { // A BRIDGE CREDIT IS A TRANSACTION — idempotent by commitment
    pub use usdm_ledger::bridge_credit_tx::*;
    #[cfg(test)]
    #[path = "node_tests.rs"]
    mod tests;
}
pub use usdm_ledger::lifecycle;
pub use usdm_ledger::merkle;
pub use usdm_ledger::mix;
pub use usdm_ledger::names;
pub use usdm_ledger::nf_oblivious;
pub use usdm_ledger::nf_evidence;
pub use usdm_ledger::join_proof;
pub use usdm_ledger::nf_sparse;
pub mod canon_chain; // A-F114 phase 2: the canonical tag chain a constant node holds (hash chain, never a sum)
/// The standing wiring census: every production function must be called by production code.
/// Test-only; compiles out entirely. See the module docs for the class it exists to catch.
#[cfg(all(test, feature = "pins-core"))]
mod wiring_census;
pub mod node;
pub mod node_runtime;
pub use usdm_ledger::note_scan;
pub use usdm_ledger::nullifier_tree;
pub use usdm_ledger::oli; // Oblivious Locator Index — sub-second cold restore (address-carried locators + LWE-PIR lookup)
pub use usdm_ledger::pir_ypir; // DB-223 §12i YPIR+SP hint-free payload PIR — standalone, nothing wired yet
pub use usdm_ledger::respend; // DB-358: first spender of a nullifier in canonical order counts; decided at the record fold
pub use usdm_ledger::keystore; // custody keys sealed at rest under the operator passphrase (EIP-2335 shape, Balloon-blake3 + EtM)
#[cfg(all(test, feature = "pins-core"))]
mod respend_door_tests; // DB-358 (1): a spend may consume only a FOLDED record, pinned at the production doors
/// Packed-LWE OMR DETECTION-CLUE primitive — the ONE implementation the whole ecosystem links. It lives in the
/// NODE crate because it is protocol crypto and the dependency direction is wallet → node (the wallet cannot be
/// the source without inverting that). The wallet re-exports THIS module, so a clue sealed by any sender is
/// detected identically by the desktop wallet, the iPhone in-process node, and the daemon — no second copy to
/// drift. Its whole purpose is making detection cost O(owned) instead of O(chain).
pub use usdm_ledger::omr;
pub mod peer_directory;
/// Pure peg arithmetic (withdrawal fee curve) — zero-dep, Kani-provable.
pub use usdm_ledger::peg_arith;
/// Bidirectional PEG reserve ledger: peg-in (mint) + peg-out (burn/redeem) for BTC + XMR, threshold-gated,
/// with the solvency + conservation (funds-can't-be-lost) invariants adversarially proven.
pub use usdm_ledger::peg;
pub use usdm_ledger::peg_in_tx;
pub use usdm_ledger::peg_attest; // THE PEG-IN ATTESTATION LANE — a t-of-n custody quorum gathers its signatures over gossip
pub use usdm_ledger::peg_out_tx;
pub use usdm_ledger::peg_pool; // DB-112 — the PQ peg pool: ladder denominations, CoinJoin-shaped batches, derived sequence
pub mod defi_batch { // §BR-15 §18.8 — the private DeFi layer's chain objects: sealed orders, the audited settlement, expiry, the claim
    pub use usdm_ledger::defi_batch::*;
    #[cfg(all(test, feature = "pins-node"))]
    #[path = "pins_node_tests.rs"]
    pub(crate) mod pins;
}
pub use usdm_ledger::defi_clear; // §BR-15 — the batch clearing rule and its threshold computation (a measured prototype; no door opened)
pub use usdm_ledger::defi_earn; // ⭐ EARN — the providers' arithmetic: the Earn batch number, the roots on the tick grid, deposit and withdrawal terms
pub mod ion_pool_tx { // IonSwap pools: the two chain objects a block carries for a pool, Class::IonOrder 55 and Class::IonSettle 56
    pub use usdm_ledger::ion_pool_tx::*;
    #[cfg(all(test, feature = "pins-core"))]
    #[path = "node_tests.rs"]
    mod node_tests;
}
pub use usdm_ledger::ion_pool; // IonSwap pools: the arithmetic of a block's batch, shares, the launch curve and the fee split (no door yet; docs/IONSWAP-POOLS-SPEC-20261110.md)
pub use usdm_ledger::defi_handover; // §BR-15 §18.11 — the custody handover: the pool re-shared to the bonded custody set, as shares throughout
pub use usdm_ledger::defi_launch; // §BR-15 §18.3 — the keyless launch position: the genesis book from the set-aside's remainder, verified at boot
pub use usdm_ledger::defi_mpc_net; // §BR-15 §18.9 — one custodian's own MPC engine: its share only, its own randomness, its links to the others
pub use usdm_ledger::defi_custody;
pub mod defi_lane; // §BR-15 §18.9 — the DeFi custodian lane: handshake, engine messages and parts over gossip; its file; the node host
#[cfg(test)]
mod defi_acceptance_tests; // §BR-15 §18.6 — the named acceptance pins over the real objects, verdicts and proofs // §BR-15 §18.8 — the custody runtime: the set settles its batch over Shamir shares (tick, booking, audit bits), then proves its audits
#[cfg(all(test, feature = "pins-core"))]
mod bridge_linkability; // §BR-0: the bridge linkability attacker — a payout piece names its deposit at most 1 in 20 (spec §5)
#[cfg(all(test, feature = "pins-core"))]
mod swap_linkability; // §SWAP-0: the swap linkability attacker — both public chains of a native swap, linked no better than a blind pick
#[cfg(all(test, feature = "pins-core"))]
mod peg_nowait; // §BR-0: the no-wait census — legitimate mint/deposit/withdrawal/redemption complete at every bond level (spec §5)
/// ⭐ DB-237 — the private stake: stake, claim and unstake as ONE chain object (the `YieldClaim` class tag).
pub use usdm_ledger::stake_tx;
/// ⭐ LIQUIDATION SPEC §10 — the stability-pool deposit as a chain object.
pub use usdm_ledger::pool_tx;
/// ⛔⛔⛔ DB-124 — the ≥2/3-attested price mark: what ONE external atomic unit is worth. Without it the peg
/// counted a piconero as a USDm cent and 1 XMR could mint ~$6.67B at the 150% ratio.
pub use usdm_ledger::order_post_tx;
pub use usdm_ledger::price_mark_tx;
pub use usdm_ledger::price_history;
pub use usdm_ledger::shamir; // §BR-5: Shamir secret sharing over GF(2^8) — the cash-out ticket key, t = ceil(2n/3) of custody
pub use usdm_ledger::epoch_key; // §BR-9a: the per-epoch threshold key — dealer-free lattice DKG, one ciphertext per ticket
pub use usdm_ledger::timelock; // §BR-9b: the no-holder hash-chain timelock, prototyped and measured (spec §20)
pub use usdm_ledger::eth_tx; // AN ETHEREUM TRANSACTION, ENCODED AND SIGNED BY THE NODE (bridge endpoint)
pub use usdm_ledger::eth_vault; // THE ETHEREUM VAULT, THE NODE'S SIDE: the IonVault contract's arithmetic, mirrored byte for byte (bridge endpoint)
pub use usdm_ledger::epoch_deal_tx; // §BR-9a step (b): a custodian's epoch-key deal and the fold's epoch-key ledger
pub use usdm_ledger::epoch_release; // §BR-9a step (c): the sealed epoch release, per-dealer fraud proofs, the ticket sealed to its epoch
pub use usdm_ledger::epoch_fraud_tx; // §BR-9a step (c): Class::EpochKeyFraud — a convicted epoch-key dealer slashed at the bond step
pub use usdm_ledger::price_relay; // §21: the onion price relays — verified list, parsers, sampling, the two-network median
pub use usdm_ledger::validator_activity; // §22: activity as chain state, bench from selection, 7-day unbond, uptime pay, operator-first slash
pub use usdm_ledger::btc_filter; // §22 6: the bundled Bitcoin watcher's core — BIP 157/158 filters, PoW + retarget, three-peer agreement
pub use usdm_ledger::keep_awake; // §22 7: the OS keep-awake a validator holds with its operator's consent, while seated
pub use usdm_ledger::btc_p2p; // §22 6: the bundled Bitcoin watcher's wire — framing, BIP 157 messages, witness blocks, SOCKS5 to onion
pub use usdm_ledger::btc_neutrino; // §22 6: the bundled Bitcoin watcher — three-peer filter agreement, committed blocks, coins
pub mod xmr_daemons; // §22 6: a Monero deposit counts only when three onion daemons agree on its block
pub mod xmr_supervisor; // §22 6: the custodian's monero-wallet-rpc, run by the node against onion daemons — no local Monero node
pub use usdm_ledger::entry_mix; // §BR-6: the entry mix — WabiSabi-shaped credential CoinJoin with MonerousD notes as credentials
pub use usdm_ledger::cashout_ticket; // §BR-5: the constant-width, redeem-commit-bound cash-out ticket // §BR-4: the 7-day TWAP and the 30-day low over the certified marks (Uniswap v2/v3 oracle shape)
/// DB-240 — the price-quote lane: a bonded validator's own signed observation, the gatherer's bounded book,
/// and the ≥2/3 quorum read a publisher needs to put a `PriceMark` on chain.
pub use usdm_ledger::price_quote;
/// ⛔⛔⛔ THE SECURITY BUDGET — the retention endowment that pays for note retention, priced by a
/// CONTROLLER over observed state rather than by a forecast about storage prices. Zero issuance.
pub use usdm_ledger::economics;
pub use usdm_ledger::node_files; // DB-341: the one state directory and served port every per-node file is named through (below the node)
pub mod persist;
/// #73 PoUW base hash seam. The PoUW hash on EVERY device is the pure-Rust Poseidon2-KoalaBear PQ
/// kernel. There is NO classical branch and no build flag that selects one: the C RandomX fallback
/// was removed at the source 2026-07-14 (`pouw`, Cargo.toml), and the `pq-randomx` feature that once
/// gated it no longer exists in `[features]`.
pub use usdm_ledger::pouw;
/// #73 PoUW engine — the balanced puzzle + non-outsourceable spend-key proof (`pi`): challenge, target,
/// per-node coinbase secrets, and the WHIR pow-bind prove/verify glue ([`whir_decider`]).
pub use usdm_ledger::pow;
/// SHARED-KERNEL PQ-PoW (the PQ-PoUW kernel) — a memory-hard PoW hash on the prover's OWN Poseidon2-KoalaBear
/// kernel (mining hardware == proving hardware). Pure Rust; the DEFAULT kernel on every device
/// (docs/POUW_SHARED_KERNEL_DESIGN.md).
pub use usdm_ledger::pow_pq_kernel;
pub use usdm_ledger::bond_tally;
pub mod pqauth {
    pub use usdm_ledger::pqauth::*;
    #[cfg(all(test, feature = "pins-core"))]
    mod af47_pins;
}
pub use usdm_ledger::pqkem;
pub use usdm_ledger::protocol;
pub use usdm_ledger::psm;
pub use usdm_ledger::reward;
pub use usdm_ledger::sat_bond_tx; // Class::SatBond: the CUSTODY bond in SAT (docs/SATOSHI-NATIVE-TOKEN.md §6, closes DB-391)
pub use usdm_ledger::quorum_math; // the two-thirds thresholds of every bonded tally: exact, Kani-proven (kani-proofs)
pub use usdm_ledger::sat_schedule; // SAT issuance schedule + custody pendulum: pure arithmetic, Kani-proven (kani-proofs)
pub use usdm_ledger::satoshi; // SATOSHI (SAT): the native token, issued only as the per-block mining reward (docs/SATOSHI-NATIVE-TOKEN.md)
pub use usdm_ledger::miner_payout_tx; // §BR-11: Class::MinerPayout — the miner pool's constant per-block payout (spec §9, §16)
pub use usdm_ledger::release_attestation_tx; // §BR-10: Class::ReleaseAttestation — builders' signed reproducible-build attestations
pub mod release_verify; // T6: `usdmd-node verify-release` — SHA256SUMS + ≥ 2 builders' attestations, before the first run
pub mod block_part; // ⭐ R4 — a pulled block crosses every bulk lane in parallel and is judged whole
pub use usdm_ledger::custody_vaults; // ⭐ SAFE AT SCALE — the bonded set cut into custody committees of 8 to 16 (stage V1: the function and its invariants)
pub use usdm_ledger::vault_merge_tx; // ⭐ SAFE AT SCALE — `Class::VaultMerge`: a custody vault at half strength or under hands its ledgers to another vault
pub mod canon_carrier_core; // ⭐ A-F114 — the one absence carrier (the wallet and the custody cover carrier)
pub use usdm_ledger::release_confirm_tx; // ⭐ A-F114 — `Class::ReleaseConfirm`: a payout's release as a chain object
pub use usdm_ledger::reserve_cost_tx; // ⭐ SAFE AT SCALE — `Class::ReserveCost`: a vault's reserve falls by the public fee its custody paid a foreign chain to move its own coins
pub use usdm_ledger::vault_rebalance_tx; // ⭐ SAFE AT SCALE, stage three — `Class::VaultRebalance`: part of one custody vault's ledgers moves to another vault, by proof (spec §3g)
pub use usdm_ledger::vault_key_tx; // ⭐ SAFE AT SCALE, stage three — `Class::VaultKey`: a custody vault takes the key of its members, or retires a key it replaced
pub mod sealed_body; // ⭐ SPEED — a large lane message is announced by id and pulled over the bulk lanes, like a block
pub mod release; // ⭐⭐ §BR-10 — a release downloads over Tor from many nodes, content-addressed (BitTorrent v2's per-piece Merkle root)
pub use usdm_ledger::deployment_signal_tx; // §BR-10: Class::DeploymentSignal — the validators' half of bicameral activation
pub use usdm_ledger::deployment; // §BR-10: signalled deployments — BIP9 version bits, bicameral activation (DB-392)
pub use usdm_ledger::sat_set_aside; // §BR-13: Class::SatSetAside — the developer SAT set-aside, proven ≤ 2M SAT (spec §11)
pub use usdm_ledger::bounty_payout_tx; // §BR-10 / spec §8.4: Class::BountyPayout — the bug bounty from the surplus buffer
pub use usdm_ledger::bond_yield_claim_tx; // §BR-3 17.6: Class::BondYieldClaim — a validator's own-weight bonders' yield (spec §17)
pub use usdm_ledger::sat_delegation_tx; // §BR-3 17.3/17.4: Class::SatDelegation — delegated SAT bonds as asset-tag conversion (spec §17)
#[cfg(all(test, feature = "pins-harness"))]
mod satoshi_pins; // the issuance door through a peer fed only blocks: honest, wrong key, forged, doubled, replayed, cap
#[cfg(test)]
mod db395_pins; // DB-395: the sender of a note holds no spend authority over it and cannot compute its nullifier (on a peer)
#[cfg(all(test, feature = "pins-harness"))]
mod db396_pins; // DB-396: a band that cannot keep up makes the fold WAIT at the lag cap, never drop a step (on a peer)
pub mod rpc;
pub mod rpc_http;
/// In-process node serve orchestrator ([`serve::run_in_process`]) — the entry the wallet (Tauri/iOS) calls to
/// spawn the phone's OWN node on a background thread binding loopback RPC, with no subprocess / no C dylib.
pub mod serve;
/// HF44 private L2-settlement carrier (verify-if-present, state-root-chained, fail-closed seam).
pub use usdm_ledger::settlement;
pub use usdm_ledger::site;
/// MonerousD Veil, build step 1: `.mud` names, chunked site roots, a chunk's shard and its holders.
pub mod veil;
pub mod veil_lane;
/// MonerousD Veil search: every published site, read by what its own front page says, searched on this node alone.
pub mod veil_search;
/// D4 availability: the ring of applied calls' sealed storage blobs a back end's readers rebuild its state from.
pub mod contract_blobs;
pub use usdm_ledger::claim_watch;
/// HF38 confidential reserve-solvency carrier (verify-if-present, fail-closed seam).
pub use usdm_ledger::solvency;
pub mod sovereign;
pub use usdm_ledger::spend_frontier;
pub mod spend_lock;
pub mod sync;
/// THE CROSS-NODE TEST STANDARD, enforced by the suite over its own source (user 2026-07-27:
/// "cross device + cross node on EVERY test is the standard").
#[cfg(test)] // audit/lint suite: it must not ship inside the production node binary
pub mod test_standard;
/// ALWAYS-UP Tor SOCKS supervisor: the node auto-spawns + KeepAlive-supervises its own `tor` so onion
/// connectivity (gossip mesh + bridge watch) is never a flaky external dependency, and a node can run
/// onion-only on any device (incl. a phone) with nothing external to configure.
pub use usdm_ledger::tor_supervisor;
/// The UNSPENT-NOTE accumulator: spend by DELETION, so state is a function of circulating supply rather than
/// history. See the module docs for why the nullifier model cannot meet the zero-growth /goal.
pub use usdm_ledger::unbond_tx;
pub use usdm_ledger::equivocation_tx;
pub use usdm_ledger::finality_vote_tx; // Class::FinalityVote: a finality vote the block carries (G2 2026-10-22: finality is one function of the chain)
/// ⛔ DB-274 P4b — a reserve THEFT slash as a CHAIN OBJECT (offenders bound in the certificate, applied at the fold).
pub use usdm_ledger::theft_tx;
/// ⭐ §CW — a validator seat as a CHAIN OBJECT (free while the reserve is zero), replacing the env self-bond.
pub use usdm_ledger::membership_bond_tx;
pub use usdm_ledger::validator;
// DB-370 — slashing protection: a validator never signs a second block at a height it already voted, across restarts.
pub mod vote_guard;
pub use usdm_ledger::vdf_clock;
/// The node's ONE proof surface — pure-Rust HVZK-WHIR via the small vendored `usdm-decider` crate:
/// the whole-chain block decider (DSYNC adopt gate), the direct per-tx spend gate (Send / bond / …),
/// and the #73/#142 coinbase pow-bind. Identical on every device; the retired pqpool STARK-era FFI is
/// DELETED (never linked).
pub use usdm_ledger::whir_decider;
pub mod xmr_watch;
