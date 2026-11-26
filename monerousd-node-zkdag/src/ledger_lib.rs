// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — THE LEDGER CRATE (`usdm-ledger`, node split stage B, lane dcash 2026-11-11). Every chain object, the
//! block and its proofs' statements, the nullifier and membership sets, the peg ledger, the DAG order and the validator set:
//! everything a node decides a block BY, compiled apart from the node that runs it (`usdmd-node`: the fold driver, the
//! runtime, the transport, the custody lanes, the RPC). The files stay in `src/` beside the node's own; the node re-exports
//! each module at its old path (`crate::block::…`), so no caller changed.
//! WHY (user 2026-11-11: "fix the node issue in which 1 edit causes a whole recompile"): the node was one crate of 364,835
//! lines and its pin builds are not incremental (`.cargo/config.toml`), so every edit rebuilt all of it. An edit in the node
//! crate now leaves this crate built; this crate's own tests build as their own binary.
//! THE RULE THIS CRATE KEEPS: nothing here names the node. A module's node half (its apply at the fold, a verdict that
//! reads node state) lives in `node::objects::<module>`; a test that drives a `Node` lives in the node crate at
//! `src/<module>/<test module>.rs`, under the same test path.
//! TEST HOOKS: every `#[cfg(test)]` here keeps its spelling. The node's tests need the ledger's test hooks (a simulated
//! node's own datadir, the census recorder, test-only constructors), so `ledger/build.rs` sets `cfg(test)` on this crate when
//! its `test-hooks` feature is on — which only the node's DEV-dependency turns on. A release build never carries a hook,
//! and every source census that recognises `#[cfg(test)]` reads this crate exactly as it read the single crate.
#![cfg_attr(feature = "test-hooks", allow(dead_code, unused_imports))]

pub mod account_da;
pub mod address;
pub mod asset_tx; // AN ASSET IS A CHAIN OBJECT: token/NFT creation and supply mint as transactions
pub mod block;
pub mod bond_tally;
pub mod bond_yield_claim_tx; // §BR-3 17.6: Class::BondYieldClaim — a validator's own-weight bonders' yield (spec §17)
pub mod bounty_payout_tx; // §BR-10 / spec §8.4: Class::BountyPayout — the bug bounty from the surplus buffer
/// Buy-USDm atomic-swap BRIDGE: real threshold-custodied taproot deposit address (secp256k1, bridge
/// endpoint) + the sound PQ t-of-n threshold mint (`authorize_mint`) the whole swap is proven against.
pub mod bridge;
pub mod bridge_assets; // THE ONE TABLE OF BRIDGE COINS: every door, route, wallet and app reads which coins the bridge holds from here
pub mod bridge_credit_tx; // A BRIDGE CREDIT IS A TRANSACTION — idempotent by commitment
pub mod btc_filter; // §22 6: the bundled Bitcoin watcher's core — BIP 157/158 filters, PoW + retarget, three-peer agreement
pub mod btc_neutrino; // §22 6: the bundled Bitcoin watcher — three-peer filter agreement, committed blocks, coins
pub mod btc_p2p; // §22 6: the bundled Bitcoin watcher's wire — framing, BIP 157 messages, witness blocks, SOCKS5 to onion
#[cfg(any(test, feature = "bridge-test-oracle"))]
pub mod btc_sim; // §NETSIM-LAUNCH — the SIMULATED Bitcoin (Core regtest semantics on the sim clock) every bridge flow runs against in netsim
pub mod btc_tx; // DB-121 — the Bitcoin exit leg: k-of-n OP_CHECKSIGADD custody script, taproot output, BIP-341 sighash, witness
/// REAL Bitcoin deposit watcher (bridge endpoint): each validator independently reads the external chain's
/// confirmed-balance data for the reserve address, so USDm mints ONLY after a real on-chain deposit confirms.
pub mod btc_watch;
pub mod budget_clock; // PERF TIER step 1: per-tick work budgets read wall time on a daemon, CPU time on a simulated node
pub mod cashout_ticket; // §BR-5: the constant-width, redeem-commit-bound cash-out ticket // §BR-4: the 7-day TWAP and the 30-day low over the certified marks (Uniswap v2/v3 oracle shape)
pub mod chain_object; // WHAT THE MEMPOOL MAY CARRY — one place naming every consensus object class
pub mod claim_watch;
pub mod clue_registry;
pub mod consensus;
pub mod contract_state; // §BR-12 L1: the ONE contract-state root (a depth-256 Poseidon2 sparse map, the node holds the root alone)
pub mod cover;
pub mod custody_vaults; // ⭐ SAFE AT SCALE — the bonded set cut into custody committees of 8 to 16 (stage V1: the function and its invariants)
pub mod da;
pub mod chain_timing; // the measured frame + the derived rates: one source for the DAA's target and the SAT schedule
pub mod dag;
pub mod debt_units; // §BR-4/§BR-7: borrowing against Bitcoin as standard debt units (public cell counts, band epochs)
pub mod decider;
pub mod decoy_tx; // §BR-8 B8-a: conditional decoys — the batch booking and the return
pub mod defi_batch; // §BR-15 §18.8 — the private DeFi layer's chain objects: sealed orders, the audited settlement, expiry, the claim
pub mod defi_clear; // §BR-15 — the batch clearing rule and its threshold computation (a measured prototype; no door opened)
pub mod defi_custody;
pub mod defi_earn; // Earn step 2 — the providers' arithmetic: a SAT deposit's units and an Earn batch's withdrawal, on the tick grid
pub mod defi_handover; // §BR-15 §18.11 — the custody handover: the pool re-shared to the bonded custody set, as shares throughout
pub mod defi_launch; // §BR-15 §18.3 — the keyless launch position: the genesis book from the set-aside's remainder, verified at boot
pub mod defi_mpc_net; // §BR-15 §18.9 — one custodian's own MPC engine: its share only, its own randomness, its links to the others
pub mod deployment; // §BR-10: signalled deployments — BIP9 version bits, bicameral activation (DB-392)
pub mod deployment_signal_tx; // §BR-10: Class::DeploymentSignal — the validators' half of bicameral activation
pub mod directory;
pub mod dir_entry_tx; // audit F15: a directory entry reaches the chain only as an object that pays for its bytes (Class::DirEntry, byte 53)
/// DSOL v2 — the node's post-quantum, 100%-private smart-contract layer (the language custom tokens,
/// NFTs, AMM pools, and wrapped coins are written in). PQ at every layer by construction; proven, not
/// asserted, via `dsol::dsol_layer_manifest`.
pub mod dsol;
pub mod dsol_call_tx; // §BR-12 L2: a proven DSOL contract call is a chain object applied at the fold (Class::DsolCall, byte 18)
pub mod dsol_deploy_tx; // §BR-12 L1: a DSOL contract deploy is a chain object applied at the fold (Class::DsolDeploy, byte 19)
pub mod dsol_fee_update_tx; // §BR-12 L3: the deployer's tighten-only publisher-fee update (Class::DsolFeeUpdate, byte 37)
/// ⛔⛔⛔ THE SECURITY BUDGET — the retention endowment that pays for note retention, priced by a
/// CONTROLLER over observed state rather than by a forecast about storage prices. Zero issuance.
pub mod economics;
pub mod entry_mix; // §BR-6: the entry mix — WabiSabi-shaped credential CoinJoin with MonerousD notes as credentials
pub mod eth_tx; // AN ETHEREUM TRANSACTION, ENCODED AND SIGNED BY THE NODE: the envelope a vault call rides (bridge endpoint)
pub mod eth_vault; // THE ETHEREUM VAULT, THE NODE'S SIDE: every value the IonVault contract computes, computed the same way (bridge endpoint)
pub mod epoch_deal_tx; // §BR-9a step (b): a custodian's epoch-key deal and the fold's epoch-key ledger
pub mod epoch_fraud_tx; // §BR-9a step (c): Class::EpochKeyFraud — a convicted epoch-key dealer slashed at the bond step
pub mod epoch_key; // §BR-9a: the per-epoch threshold key — dealer-free lattice DKG, one ciphertext per ticket
pub mod epoch_release; // §BR-9a step (c): the sealed epoch release, per-dealer fraud proofs, the ticket sealed to its epoch
pub mod equivocation_tx;
pub mod faucet;
pub mod finality_vote_tx; // Class::FinalityVote: a finality vote the block carries (G2 2026-10-22: finality is one function of the chain)
pub mod fixed;
pub mod ghostdag;
pub mod governance;
pub mod hash;
pub mod ion_pool_tx; // IonSwap pools: the two chain objects a block carries for a pool, Class::IonOrder 55 and Class::IonSettle 56; a pool's row is a leaf of the contract-state root
pub mod ion_pool; // IonSwap pools: the arithmetic of a block's batch, shares, the launch curve and the fee split (no door yet; docs/IONSWAP-POOLS-SPEC-20261110.md)
pub mod join_proof;
pub mod keep_awake; // §22 7: the OS keep-awake a validator holds with its operator's consent, while seated
pub mod keystore; // custody keys sealed at rest under the operator passphrase (EIP-2335 shape, Balloon-blake3 + EtM)
pub mod letter;
pub mod lifecycle;
pub mod liquidation; // THE COLLATERAL LIQUIDATION LANE — the aggregate-ratio invariant + the crash simulation
pub mod liquidation_tx; // A LIQUIDATION IS A CHAIN OBJECT — the block-carried form of a collateral re-mark
pub mod local_origin; // DB-374: the local HTTP servers answer only the user's own software (Host / Origin / Sec-Fetch-Site)
pub mod log_cap; // a node bounds its own stderr on disk (2026-09-03: unbounded launchd logs)
/// ⭐⭐⭐ DB-223 — the block's MEMBERSHIP TRANSITION: one aggregate over the spends' member-path carriers, proving every
/// spend input is a leaf under an anchor the door checks against its own ring, naming no record.
pub mod member_transition;
/// ⭐ §CW — a validator seat as a CHAIN OBJECT (free while the reserve is zero), replacing the env self-bond.
pub mod membership_bond_tx;
pub mod mempool;
pub mod merkle;
pub mod miner;
pub mod miner_payout_tx; // §BR-11: Class::MinerPayout — the miner pool's constant per-block payout (spec §9, §16)
pub mod mix;
pub mod names;
pub mod net;
pub mod nf_evidence;
pub mod nf_oblivious;
pub mod nf_sparse;
pub mod node_files; // DB-341: the one state directory and served port every per-node file is named through (below the node)
pub mod note_scan;
/// ⭐⭐⭐ §BA/§BB — the block's NOTE TRANSITION as evidence a peer can check holding no transaction
/// body: one bound aggregate plus the tuple list it stands over, and an ALLOW-list built from that list.
pub mod note_transition;
pub mod nullifier_tree;
pub mod oli; // Oblivious Locator Index — sub-second cold restore (address-carried locators + LWE-PIR lookup)
/// Packed-LWE OMR DETECTION-CLUE primitive — the ONE implementation the whole ecosystem links. It lives in the
/// NODE crate because it is protocol crypto and the dependency direction is wallet → node (the wallet cannot be
/// the source without inverting that). The wallet re-exports THIS module, so a clue sealed by any sender is
/// detected identically by the desktop wallet, the iPhone in-process node, and the daemon — no second copy to
/// drift. Its whole purpose is making detection cost O(owned) instead of O(chain).
pub mod omr;
pub mod order_book; // resting orders in DA/gossip — the DEX book, never consensus state
pub mod order_fill_tx; // A FILL IS A TRANSACTION — the on-chain form of a DEX trade
/// ⛔⛔⛔ DB-124 — the ≥2/3-attested price mark: what ONE external atomic unit is worth. Without it the peg
/// counted a piconero as a USDm cent and 1 XMR could mint ~$6.67B at the 150% ratio.
pub mod order_post_tx;
pub mod oscall; // lane d 2026-10-27: every OS call through a safe wrapper crate — no `unsafe` in the shipping tree
pub mod params;
/// Bidirectional PEG reserve ledger: peg-in (mint) + peg-out (burn/redeem) for BTC + XMR, threshold-gated,
/// with the solvency + conservation (funds-can't-be-lost) invariants adversarially proven.
pub mod peg;
/// Pure peg arithmetic (withdrawal fee curve) — zero-dep, Kani-provable.
pub mod peg_arith;
pub mod peg_attest; // THE PEG-IN ATTESTATION LANE — a t-of-n custody quorum gathers its signatures over gossip
pub mod peg_in_tx;
pub mod peg_out_tx;
pub mod peg_pool; // DB-112 — the PQ peg pool: ladder denominations, CoinJoin-shaped batches, derived sequence
pub mod pir_ypir; // DB-223 §12i YPIR+SP hint-free payload PIR — standalone, nothing wired yet
/// ⭐ LIQUIDATION SPEC §10 — the stability-pool deposit as a chain object.
pub mod pool_tx;
pub mod pot_fill_tx; // §BR-3 17.5 layer 1: the repayment pot sold at the floor, its proceeds retired by custody
/// #73 PoUW base hash seam. The PoUW hash on EVERY device is the pure-Rust Poseidon2-KoalaBear PQ
/// kernel. There is NO classical branch and no build flag that selects one: the C RandomX fallback
/// was removed at the source 2026-07-14 (`pouw`, Cargo.toml), and the `pq-randomx` feature that once
/// gated it no longer exists in `[features]`.
pub mod pouw;
/// #73 PoUW engine — the balanced puzzle + non-outsourceable spend-key proof (`pi`): challenge, target,
/// per-node coinbase secrets, and the WHIR pow-bind prove/verify glue ([`whir_decider`]).
pub mod pow;
/// SHARED-KERNEL PQ-PoW (the PQ-PoUW kernel) — a memory-hard PoW hash on the prover's OWN Poseidon2-KoalaBear
/// kernel (mining hardware == proving hardware). Pure Rust; the DEFAULT kernel on every device
/// (docs/POUW_SHARED_KERNEL_DESIGN.md).
pub mod pow_pq_kernel;
pub mod pqauth;
pub mod pqkem;
pub mod price_history;
pub mod price_mark_tx;
/// DB-240 — the price-quote lane: a bonded validator's own signed observation, the gatherer's bounded book,
/// and the ≥2/3 quorum read a publisher needs to put a `PriceMark` on chain.
pub mod price_quote;
pub mod price_relay; // §21: the onion price relays — verified list, parsers, sampling, the two-network median
pub mod protocol;
pub mod psm;
pub mod quorum_math; // the two-thirds thresholds of every bonded tally: exact, Kani-proven (kani-proofs)
pub mod relay;
pub mod release_attestation_tx; // §BR-10: Class::ReleaseAttestation — builders' signed reproducible-build attestations
pub mod reserve_cost_tx; // ⭐ SAFE AT SCALE — `Class::ReserveCost`: a vault's reserve falls by the public fee its custody paid a foreign chain to move its own coins
pub mod release_confirm_tx; // ⭐ A-F114 — a payout's release as a chain object (increment 1: the type; not framed yet)
pub mod respend; // DB-358: first spender of a nullifier in canonical order counts; decided at the record fold
pub mod reward;
pub mod sat_bond_tx; // Class::SatBond: the CUSTODY bond in SAT (docs/SATOSHI-NATIVE-TOKEN.md §6, closes DB-391)
pub mod sat_delegation_tx; // §BR-3 17.3/17.4: Class::SatDelegation — delegated SAT bonds as asset-tag conversion (spec §17)
pub mod sat_schedule; // SAT issuance schedule + custody pendulum: pure arithmetic, Kani-proven (kani-proofs)
pub mod sat_set_aside; // §BR-13: Class::SatSetAside — the developer SAT set-aside, proven ≤ 2M SAT (spec §11)
pub mod satoshi; // SATOSHI (SAT): the native token, issued only as the per-block mining reward (docs/SATOSHI-NATIVE-TOKEN.md)
/// HF44 private L2-settlement carrier (verify-if-present, state-root-chained, fail-closed seam).
pub mod settlement;
pub mod shamir; // §BR-5: Shamir secret sharing over GF(2^8) — the cash-out ticket key, t = ceil(2n/3) of custody
pub mod site;
/// HF38 confidential reserve-solvency carrier (verify-if-present, fail-closed seam).
pub mod solvency;
pub mod spend_frontier;
/// ⭐ DB-237 — the private stake: stake, claim and unstake as ONE chain object (the `YieldClaim` class tag).
pub mod stake_tx;
#[cfg(any(test, feature = "bridge-test-oracle"))]
pub mod test_ports; // 2026-10-27 — per-instance loopback port blocks for the external processes a test raises (Bitcoin Core test_framework shape)
pub mod theft_repayment_tx; // §BR-3 17.5: a custody theft repaid in layers (pot, buffer, pool, haircut) as a chain object
/// ⛔ DB-274 P4b — a reserve THEFT slash as a CHAIN OBJECT (offenders bound in the certificate, applied at the fold).
pub mod theft_tx;
pub mod timelock; // §BR-9b: the no-holder hash-chain timelock, prototyped and measured (spec §20)
/// ALWAYS-UP Tor SOCKS supervisor: the node auto-spawns + KeepAlive-supervises its own `tor` so onion
/// connectivity (gossip mesh + bridge watch) is never a flaky external dependency, and a node can run
/// onion-only on any device (incl. a phone) with nothing external to configure.
pub mod tor_supervisor;
/// The UNSPENT-NOTE accumulator: spend by DELETION, so state is a function of circulating supply rather than
/// history. See the module docs for why the nullifier model cannot meet the zero-growth /goal.
pub mod unbond_tx;
pub mod unit_close_tx; // §BR-4 B4-3: one debt unit closed — debt burned, collateral returned in payout pieces (Class::UnitClose)
pub mod unit_open_tx; // §BR-4 B4-2: one debt unit opened against one co-signed Bitcoin deposit (Class::UnitOpen)
pub mod validator;
pub mod validator_activity; // §22: activity as chain state, bench from selection, 7-day unbond, uptime pay, operator-first slash
pub mod vault_key_tx; // ⭐ SAFE AT SCALE, stage three — `Class::VaultKey`: a custody vault takes the key of its members, or retires a key it replaced
pub mod vault_rebalance_tx; // ⭐ SAFE AT SCALE, stage three — `Class::VaultRebalance`: part of one custody vault's ledgers moves to another vault, by proof (spec §3g)
pub mod vault_merge_tx; // ⭐ SAFE AT SCALE — `Class::VaultMerge`: a custody vault at half strength or under hands its ledgers to another vault
pub mod vdf_clock;
pub mod verify_cache; // a block's transition proofs verify once per node (Bitcoin's script-execution cache)
/// The node's ONE proof surface — pure-Rust HVZK-WHIR via the small vendored `usdm-decider` crate:
/// the whole-chain block decider (DSYNC adopt gate), the direct per-tx spend gate (Send / bond / …),
/// and the #73/#142 coinbase pow-bind. Identical on every device; the retired pqpool STARK-era FFI is
/// DELETED (never linked).
pub mod whir_decider;
pub mod window_index;
pub mod wrapped_asset_tx; // A WRAPPED-ASSET REGISTRATION IS A CHAIN OBJECT — the ratio rides a block, not a socket
pub mod wrapped_mint_tx; // A WRAPPED MINT IS A CHAIN OBJECT — the note AND the peg transition, on one object
/// The test census recorder the ledger's own `#[cfg(test)]` gates call (`vacuity::record`); the node re-exports it.
#[cfg(test)]
pub mod test_census {
    pub mod vacuity;
}
