// Copyright (c) 2026 MonerousD contributors. All rights reserved.

//! ⭐⭐⭐ WHAT THE MEMPOOL IS ALLOWED TO CARRY — ONE PLACE THAT NAMES EVERY CONSENSUS OBJECT.
//!
//! ⛔⛔⛔ THE MEMPOOL WAS SINGLE-CLASS, AND THAT IS WHY NOTHING BUT A SEND COULD REACH A BLOCK.
//!
//! MEASURED 2026-09-04. `Node::ingest_tx` admitted a transaction only if its blob passed
//! `pqspend_direct_verify_carrier` — the ZK gate for an ordinary send. Every other consensus object this
//! chain has learned to build (a DEX settlement, a bridge credit, an asset creation, an asset mint) was
//! answered `InvalidProof` at admission, no matter how sound it was. The consequence was not a missing
//! feature, it was a WRONG LEDGER: `execute_order_fill` burned a pair, dropped an order and credited three
//! notes on the node that ran it, the settlement never entered a block, and the next node settled the same
//! order again from the same bytes. The maker's lot paid out twice.
//!
//! So the gate was never really "is this a valid send?" — it was "is this the ONE class we implemented?".
//! This module makes it the question it should always have been: **is this a consensus object of a class
//! this chain knows, and does it verify under that class's own rule?**
//!
//! ⛔ A CLASS TAG IS NOT OPTIONAL. `apply_chain_dex_object` used to say a type tag was unnecessary because
//! bytes that are not a DEX object simply fail to decode. That is true for ONE reader and false for a
//! dispatcher: these objects are bare `postcard` structs, and a bare postcard decode is not injective
//! across types — a blob written as one class can parse as another and be verified under the wrong rule.
//! The whole point of admitting more than one class is that the class must be UNAMBIGUOUS, so every object
//! is framed `MAGIC || CLASS || payload` and a blob whose frame does not match is not that class. That is
//! the one-object-one-encoding law applied at the door.
//!
//! ⛔ WHAT IS DELIBERATELY *NOT* ADMITTED YET, AND WHY IT IS REFUSED RATHER THAN WAVED THROUGH. A class is
//! admissible only when a node that receives it can verify it FROM THE OBJECT ITSELF. A DEX fill can:
//! `verify_order_fill` reads the two proof halves the object carries and the chain's own fee rate, and
//! needs nothing this node was told by anybody. A bridge credit cannot yet — its authority is a reserve
//! attestation the accepting node checked, and admitting it on that node's say-so would be exactly the
//! "local decides consensus" shape this codebase has already paid for once. Those classes are NAMED here
//! and REFUSED here, loudly, so the gap is a visible fail-closed refusal instead of a silent hole.
//!
//! ⭐⭐⭐ PER-NOTE VALIDITY AT GRAFT (2026-09-06, lane B) — WHAT IS NOW BOUND, AND THE EXACT RESIDUAL.
//!
//! The settled shape this follows is Bitcoin/Kaspa's: **a block CARRIES what is needed to apply it**.
//! Here a block's applied value is its `output_notes`; the justification for each chunk is the object
//! that created it. What travels together can be bound, and is now:
//!
//! * **The wrapper↔object binding** ([`wrapper_binds_object`]): a framed object's transaction must carry
//!   BYTE-EXACTLY the notes the object itself justifies ([`carried_note_payloads`]) — enforced at
//!   `ingest_tx` (both doors), at note assembly, and at the graft door over every carried transaction the
//!   grafting node can resolve. RED-measured before it existed: a valid credit blob under a
//!   note-substituted wrapper was admitted, carried, recorded and folded on an honest peer — an
//!   any-submitter mint, no modified producer needed.
//!
//! ⛔ THE RESIDUAL, stated precisely so nobody mistakes the subset for the closure: a producer whose
//! MODIFIED binary writes naked chunks straight into `Block::output_notes` still mints on every peer
//! that cannot resolve the block's carried transactions. This is not an implementation gap — it is
//! information-theoretic under the current wire: `Block` carries `tx_ids` (content hashes) and no
//! bodies, and a body-less peer receives NO datum distinguishing "a note of a transaction I do not
//! hold" from "a naked injected chunk"; refusing unattributable chunks would therefore refuse honest
//! payments on every peer that lost a tx-gossip race (measured live as the universal case), and a
//! resolution-dependent refusal diverges honest peers from each other. The full closure requires one
//! of exactly two mechanisms, and both need arms this crate does not have yet: (a) **id-bound carried
//! justification** — an `object_set` sidecar carrying every value-bearing framed object (bound like
//! `del_set`) plus a MANDATORY per-block settlement aggregate whose public inputs bind the block's
//! output-note commitment digest (today's send carrier binds only value conservation, so this is
//! prover-lane work), both folded into the header preimage — a HARD FORK (every id moves, genesis
//! included; a coordinated reset is a user decision) plus hot-path aggregate proving the 500 ms cadence
//! must absorb; or (b) **the bonded-threshold arm** — ≥2/3 bonded attestation over block BODIES (the
//! same arm this module already names as the mainnet mint authority), which makes an unattributable
//! chunk refused by quorum instead of by each peer's luck in resolving bodies. Until one lands, the
//! staged-credit lane (`Node::stage_credit_note`: faucet drips, publish-refused peg-ins, unbond
//! returns, executor credits, stranded-note re-carries) legitimately rides blocks with NO claiming
//! transaction, so "unattributable" cannot be made refuse-worthy on its own. Adjacent finding recorded
//! for the same spec: `PqTx::nullifiers` on a NON-fill wrapper is now bound (must be empty), but a
//! fill's padded burn lane and a send's envelope nullifiers remain node-seeded/unbound to the object —
//! the send carrier must bind its nullifier and output commitments in its public IO when the prover
//! lane picks this up.

/// Frames every consensus object. Four bytes, so a legacy unframed send blob can never collide with one.
pub const MAGIC: [u8; 4] = *b"MUSD";

/// The classes of object this chain has. A number is never reused: an old blob must never re-read as a new
/// class after an upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    /// A DEX settlement: both proof halves, the terms, the burns and the three payout notes.
    OrderFill = 1,
    /// A resting offer joining the book.
    OrderPost = 2,
    /// A bridge deposit crediting a note. NOT admissible yet — see the module note.
    BridgeCredit = 3,
    /// A new asset's descriptor. NOT admissible yet — see the module note.
    AssetCreate = 4,
    /// An issuance under an existing asset. NOT admissible yet — see the module note.
    AssetMint = 5,
    /// A COLLATERAL LIQUIDATION: the >=2/3-attested re-mark that closes an under-collateralized position,
    /// seizing its collateral and retiring the USDm that collateral fetched. Carries no note of its own.
    Liquidation = 6,
    /// A WRAPPED-ASSET REGISTRATION: the >=2/3-attested, block-carried setting of a wrapped asset's
    /// collateral ratio. Carries no note of its own — it fixes the number every later mint against that
    /// asset is measured by, which is precisely why it may not be a socket-supplied local value.
    WrappedAssetRegister = 7,
    /// A WRAPPED MINT: the >=2/3-attested confidential mint of a wrapped asset, carrying BOTH the minted
    /// note and the peg commitment transition it performs. The transition is on the object because a note
    /// that travels without it leaves every other node wrong about what backs the token.
    WrappedMint = 8,
    /// AN ASSET TRANSFER: one note in, two notes out, amount AND asset hidden. The object that makes a
    /// token or an NFT spendable at all — before it, `AssetApply` covered CREATE and MINT only.
    AssetSpend = 9,
    /// ⛔⛔⛔ AN UNBOND — the authenticated RELEASE of a validator's own bond, and it moves money.
    ///
    /// MEASURED before this class existed: `Node::unbond_validator` was a LOCAL mutation, so a validator
    /// that unbonded on one node left every OTHER node counting its full weight in the ≥2/3 denominator
    /// and still holding its bonded note locked — the same bond returnable once per node. Admission
    /// already travelled (`apply_bond_set`); only the direction that hands money back did not.
    Unbond = 10,
    /// ⛔⛔⛔ §CS — A BTC/XMR PEG-IN: the ≥2/3-attested confidential mint that is how USDm comes into
    /// existence, carrying the credited note AND the peg commitment transition it performs.
    ///
    /// MEASURED before this class: `Node::peg_in_confidential` credited through `record_note_payload` and
    /// advanced `reserve_commit`/`minted_commit` on the ONE node that answered the RPC. The depositor's
    /// USDm existed nowhere else, and because the replay set and the commitments are per-node, the same
    /// attested deposit could be re-submitted to the next node and mint again. The transition is the
    /// layer, so the transition becomes an object the block carries.
    PegIn = 11,
    /// ⛔⛔⛔ §CS-b — A PEG-OUT: the ≥2/3-attested burn of USDm against a reserve release. Carries the
    /// burned note's nullifier so the burn RETIRES on every node — before this class `spent_burns` was
    /// per-node, so one USDm note could redeem once per node and drain the reserve that many times.
    PegOut = 12,
    /// ⛔⛔⛔ §CL — A STAKE-YIELD HARVEST: the carrier-authorised spend of a staked note that returns the
    /// principal and mints confidential yield. Carries the stake nullifier so the harvest RETIRES on every
    /// node — before this class `spent_burns` was per-node, so one stake harvested once per node and the
    /// staker's returned principal existed only where it was claimed.
    YieldClaim = 13,
    /// ⭐ §CW — A VALIDATOR SEAT AS A CHAIN OBJECT. The env self-bond seated a validator LOCALLY, so two
    /// peered nodes held disjoint sets and one BTC deposit minted USDm once per node. A seat now rides
    /// `Block::bond_set` beside `Unbond` and lands on every grafting node from the same bytes. Free while
    /// the reserve is zero (the adaptive rule at its zero point); no founding keys — the chain records who
    /// bonded first.
    MembershipBond = 14,
    /// ⛔⛔⛔ DB-124 — A PRICE MARK: the ≥2/3-attested, block-carried statement of what ONE external atomic
    /// unit is worth, in USDm-atomic units scaled by [`crate::liquidation::PRICE_SCALE`].
    ///
    /// MEASURED before this class existed: the peg had NO price. It counted one sat and one piconero each
    /// as one USDm atomic unit and the 150% backing check compared those raw counts, so 1 XMR (1e12
    /// piconero) could mint on the order of $6.67 BILLION against ~$150 of real collateral. The ratio
    /// check was sound; the UNIT it compared was not.
    ///
    /// It is a CLASS and not a socket read for the same reason [`Class::WrappedAssetRegister`] is: the
    /// mark decides how much USDm may be issued against a deposit, so a node that took it from an RPC
    /// would be minting against a number the chain never set. Unlike every other attested class, each
    /// attestor signs its OWN number and the door reduces them with a bond-weighted median — two honest
    /// custodians never report an identical price, so an identical-bytes tally would find a quorum only
    /// by coincidence. Carries no note of its own.
    PriceMark = 15,
    /// ⛔ DB-266 — an equivocation's EVIDENCE: two finality votes by one key at one height naming different blocks.
    /// Every node verifies it from the object's own bytes and slashes the voter at graft (it rides `bond_set`);
    /// seeing an equivocation locally only publishes it. See `equivocation_tx`.
    Equivocation = 16,
    /// ⭐⭐⭐ DB-313 §3 — THE WELDED CLASS'S AGGREGATE: ONE proof over every USDm bond a block carries
    /// ([`crate::note_transition::BondTransition`]). A PRODUCER'S block-level statement, not a transaction: it rides
    /// `Block::bond_set` beside the bonds it states and is judged at graft (`note_transition::verify_bond`). No pool
    /// door admits one. Carries no note of its own.
    BondTransition = 17,
    /// ⭐ §BR-12 L1 — A DSOL CONTRACT DEPLOY: the code, its height class, the publisher-fee manifest, the deployer's key and
    /// signature, the contract-state insertion path and the creation-price burn (`dsol_deploy_tx`). Applied at the FOLD.
    DsolDeploy = 19,
    /// ⭐ §BR-12 L2 — A DSOL CONTRACT CALL: the proven run, its libraries and code, the caller's key and signature, the state
    /// leaf's path and the fee spend paying the deployed publisher fee (`dsol_call_tx`). Applied at the FOLD.
    DsolCall = 18,
    /// ⭐ §BR-12 L3 — A TIGHTEN-ONLY PUBLISHER-FEE UPDATE: the deployer lowers its contract's fee (`dsol_fee_update_tx`). FOLD.
    DsolFeeUpdate = 37,
    /// ⭐ AUDIT F15 — A PAID DIRECTORY ENTRY: a signed @username, group handle, profile or handover, and the USDm burn that
    /// pays for the bytes every node will keep (`dir_entry_tx`). The only way an entry reaches the directory. FOLD.
    DirEntry = 53,
    /// ⭐ IONSWAP POOLS — AN ORDER: buy, sell, add liquidity, REMOVE liquidity or launch a curve; it burns its input notes by
    /// welded public-amount spends bound to its own words and joins the ledger's pending orders (`ion_pool_tx`). FOLD.
    IonOrder = 55,
    /// ⭐ IONSWAP POOLS — A SETTLEMENT: one batch of a pool, formed by any node and recomputed by every node; it carries the
    /// pool's row, its path in the contract-state root and the payout notes (`ion_pool_tx`). FOLD.
    IonSettle = 56,
    /// ⛔ DB-274 P4b (§8.15) — a reserve THEFT's evidence: a ≥2/3 certificate over the theft statement AND the offender
    /// ids it names (the v2 message). It rides `bond_set` like an equivocation and slashes at the FOLD, weighed against
    /// the step's pre-state set; the route that receives it only publishes. See `theft_tx`. Bytes 18 (`DsolCall`) and
    /// 19 (`DsolDeploy`) are reserved by the DSOL door spec.
    ReserveTheft = 20,
    /// ⭐ LIQUIDATION SPEC §10 — A STABILITY-POOL DEPOSIT: a USDm note spent into one PSM's pool, the depositor's RECEIPT
    /// (keyed to the pool's snapshot) and the change credited, the pool's committed total advanced by the same hidden `d`.
    /// Applies at its block's canonical fold. See `pool_tx`. Harness: the pool words it writes are `pools` (ChainDerived,
    /// compared, refuted) in `harness::fuzz::authority_peg`.
    PoolDeposit = 21,
    /// ⭐ LIQUIDATION SPEC §10.2 — A STABILITY-POOL WITHDRAWAL: a receipt spent (its snapshot hidden, §10.4), the compounded
    /// USDm note credited, the pool's committed total retired by the same hidden `u`. Applies at its block's fold. See
    /// `pool_tx`. Harness: the pool words it writes are `pools` (ChainDerived, compared, refuted) in
    /// `harness::fuzz::authority_peg`.
    PoolWithdraw = 22,
    /// ⭐ SATOSHI — one block's MINING REWARD in the native token (docs/SATOSHI-NATIVE-TOKEN.md): a SAT note whose
    /// asset-mint carrier opens it to the schedule's public amount at the carrying block's parent key. Carried ONLY in the
    /// credit set of the block that earned it — never pooled, never relayed (absent from `wrapper_binds_object`'s list) —
    /// and applied at that block's fold against the hard cap. See `satoshi`.
    SatoshiReward = 23,
    /// ⭐ SATOSHI §6 — A CUSTODY BOND IN SAT: a validator spends a SAT note, locking output 0 as its custody weight (welded
    /// and asset-tagged in the carrier, signed by the seating key); the change is credited. Pooled by the validator,
    /// carried in the credit set, applied at the fold (`sat_bond_tx`). Closes DB-391: custody weight is never USDm.
    SatBond = 24,
    /// ⛔ G2 (lane a 2026-10-22) — A FINALITY VOTE: one validator's signed `(block, height)`, carried in `Block::bond_set`
    /// and tallied at the carrying body's GRAFT on every node, so `(finalized_height, finalized_block)` is one function of
    /// the chain (MEASURED before: the replica census read `finality` DIFFERS 39/39 — both doors tallied on RECEIPT).
    /// Hearing a vote only pools it. Mints, moves and burns nothing. See `finality_vote_tx`.
    FinalityVote = 25,
    /// ⭐ §BR-11 — THE MINER POOL'S PER-BLOCK PAYOUT: one per block, exactly the open quarter's rate of the fee-funded miner
    /// pool, to the producer's own key (`miner_payout_tx`). Mints nothing: the fold pays it from the pool or refuses it.
    MinerPayout = 26,
    /// §BR-3 17.3/17.4 — a delegated-SAT conversion (Delegate / Undelegate / Release), `sat_delegation_tx`.
    SatDelegation = 27,
    /// §BR-3 17.6 — a validator's own-weight bonders' yield claim, `bond_yield_claim_tx`.
    BondYieldClaim = 28,
    /// §BR-10 / spec §8 item 4: the bug bounty, paid from the surplus buffer by ≥ 2/3 of custody (`bounty_payout_tx`).
    BountyPayout = 32,
    /// §BR-13 — the canonical developer SAT set-aside (one object, applied once), `sat_set_aside`.
    SatSetAside = 29,
    /// §BR-10 — a validator's deployment signal (the validators' half of bicameral activation), `deployment_signal_tx`.
    DeploymentSignal = 30,
    /// §BR-10 — a release builder's attestation, `release_attestation_tx`.
    ReleaseAttestation = 31,
    /// §BR-9a — a custodian's epoch-key deal (its public part + its seed's shares sealed per roster member),
    /// `epoch_deal_tx`. Byte 40: 33–36 are claimed by lanes not yet landed.
    EpochKeyDeal = 40,
    /// §BR-9a — a self-verifying fraud proof convicting an epoch-key dealer (its committed shares rebuild another public
    /// part), slashed in the bond step like `Equivocation`, `epoch_fraud_tx`. Byte 42: 41 is claimed by a lane not yet
    /// landed.
    EpochKeyFraud = 42,
    /// §BR-3 17.5 — a custody theft repaid in layers (pot, buffer, pool, haircut), `theft_repayment_tx`.
    TheftRepayment = 33,
    /// §BR-3 17.5 layer 1 realized — the repayment pot sold at the floor, its proceeds retired, `pot_fill_tx`.
    PotFill = 34,
    /// §BR-8 B8-a — a payout batch's decoy legs booked as obligations, `decoy_tx`.
    DecoyBatch = 35,
    /// §BR-8 B8-a — a decoy returned to the reserve, its obligation closed, `decoy_tx`.
    DecoyReturn = 36,
    /// §BR-4 B4-2 — one debt unit opened against one co-signed Bitcoin deposit, `unit_open_tx` (byte 40 is the defi lane's).
    UnitOpen = 41,
    /// §BR-4 B4-3: one debt unit closed — the unit note dies, its debt and interest are burned, custody returns the collateral
    /// (byte 43: 42 is the defi lane's `EpochKeyFraud`, landed first).
    UnitClose = 43,
    /// §BR-15 §18.8 — a sealed DeFi order: a committed USDm burn and its Shamir sharings dealt to the custody roster,
    /// `defi_batch::DefiOrderTx`.
    DefiOrder = 44,
    /// §BR-15 §18.8 — a batch's audited settlement: the tick, every custodian's audit, the claim leaves, `defi_batch::DefiSettleTx`.
    DefiSettle = 45,
    /// §BR-15 §18.8 — a batch nobody settled in its window, expired: every order's refund leaf, `defi_batch::DefiExpireTx`.
    DefiExpire = 46,
    /// §BR-15 §18.8 — a claim (or refund) that names no order, `defi_batch::DefiClaimTx`.
    DefiClaim = 47,
    /// §BR-15 §18.11 — the custody handover: the DeFi pool re-shared to the bonded custody set, `defi_handover::DefiHandoverTx`.
    DefiHandover = 48,
    /// §BR-15 §18.12 — a batch's slots: exactly `SLOTS` orders and `SLOTS` claims, real or cover, `defi_batch::DefiSlotsTx`.
    DefiSlots = 49,
    /// ⭐ EARN STEP 3 — a window's one protocol-wide income rate over every pair's closed window, `defi_batch::DefiEarnEpochTx`.
    DefiEarnEpoch = 57,
    /// SAFE AT SCALE — a custody vault under half strength hands its ledgers to another vault, `vault_merge_tx`: the
    /// two vaults, the receiving ledgers' pairs after, two sum proofs per ledger kind against the chain's own pairs, and
    /// the signatures of two thirds of EACH vault. No note: nothing is created, the retiring ledgers return to genesis.
    VaultMerge = 50,
    /// SAFE AT SCALE — a vault's reserve falls by the public fee its custody paid a foreign chain to move the vault's own
    /// coins, `reserve_cost_tx`: the ledger, the fee, the foreign transaction, the reserve after, the proof against the
    /// chain's own pair, and the signatures of two thirds of that vault. No note; one object per foreign transaction.
    ReserveCost = 51,
    /// SAFE AT SCALE, stage three — a custody vault takes the key of its members, or retires a key it replaced,
    /// `vault_key_tx`: the vault, the member set and the Monero address its wallets report (a take) or the replaced key
    /// (a retire), and the signatures of two thirds of that vault. No note and no ledger word: it moves the custody key
    /// record a leaver's collateral is released against (`PegLedger::vault_key_names`).
    VaultKey = 52,
    /// SAFE AT SCALE, stage three (spec §3g.1) — PART of one custody vault's ledgers moves to another vault in three
    /// steps, `vault_rebalance_tx`: a CARVE (the giver's part and pair after per ledger kind, two sum proofs against the
    /// chain's own pair, two thirds of the giver; the part rests in the giver's slot), a TAKE (the receiver's pair after
    /// per kind over the slot's own commitment, its bound proof after or the whole set, two thirds of the receiver) or
    /// a CANCEL (the giver's pair after, two thirds of the giver, a rotation day after the carve). No note: nothing is
    /// created, nothing is lost.
    VaultRebalance = 54,
}

impl Class {
    /// Every class this chain has, read from the decoder itself (the one place a byte becomes a class), so a census
    /// built on it covers a class the day it is added — never a hand-kept list (the rogue-role census, 2026-10-03).
    /// ⭐ §BR-13 item 4 — THE SAT-SUPPLY DOOR OF EVERY CLASS, by construction: SAT has exactly three doors (the block reward,
    /// the genesis set-aside, a spend that conserves SAT), and this match names, for EVERY class the decoder knows, how a SAT
    /// note cannot enter through it. The match has no wildcard: a class added without its door row does not compile (the
    /// SAT-supply census `sat_has_exactly_three_doors_…` went red 2026-11-02 on seven classes landed without a row — a
    /// hand-kept table in a test is a census that fires after the landing; this one fires before the build finishes).
    #[must_use]
    pub fn sat_door(self) -> &'static str {
        match self {
            Class::SatoshiReward => "DOOR 1: the block reward — the schedule's amount at the carrying block's key, capped at the fold",
            Class::SatSetAside => "DOOR 2: the canonical set-aside — one object, applied once, its note proven ≤ 2M SAT over a public input",
            Class::SatBond => "conserving: the asset-tagged bond carrier locks and returns SAT it spent",
            Class::AssetSpend => "conserving: the transfer carrier conserves value in ONE asset tag",
            Class::OrderFill => "conserving: the composed fill proof conserves each leg in its own asset",
            Class::BridgeCredit => "REFUSED: the decode refuses the SAT tag (pinned below)",
            Class::AssetMint => "REFUSED: admission refuses the SAT asset id and tag (pinned below)",
            Class::AssetCreate => "REFUSED: a creation's own supply naming the SAT asset id or tag is refused as a mint's is (`AssetCreateTx::supply_authorised`); its other notes are USDm change (a USDm out1 of the bond-validity carrier) and, when it carries no supply, the issue right (no value)",
            Class::PegIn => "USDm only: the mint carrier welds the USDm tag",
            Class::PegOut => "USDm only: the burn carrier's change is USDm",
            Class::WrappedMint => "wrapped assets only: the tag is wrapped_asset_tag(index), never the SAT tag",
            Class::YieldClaim => "USDm only: the stake carrier's principal and reward are USDm",
            Class::PoolDeposit => "USDm only: the deposit carrier binds a USDm receipt and change",
            Class::PoolWithdraw => "USDm only: the withdraw carrier binds a USDm note",
            Class::MinerPayout => "USDm only: a public-opening USDm note from the fee pool",
            Class::SatDelegation => "conserving in SAT: burns exactly what it mints across SAT / delegated / unbonding; its yield note is USDm from the bonders' pool",
            Class::BondYieldClaim => "USDm only: the yield note is a USDm mint carrier paid from the bonders' pool",
            Class::BountyPayout => "USDm only: the bounty note is a USDm mint carrier paid from the surplus buffer",
            Class::Unbond => "returns the note its bond locked (conserving), never a new one",
            Class::MembershipBond => "no note",
            Class::Equivocation => "no note",
            Class::FinalityVote => "no note",
            Class::ReserveTheft => "no note",
            Class::BondTransition => "no note",
            Class::Liquidation => "no note: a commitment re-mark",
            Class::TheftRepayment => "no note: a commitment transition (§BR-3 17.5 — the slashed SAT waits in the pot word)",
            Class::DecoyBatch => "no note: custody's own Bitcoin decoy outputs booked as obligations",
            Class::DecoyReturn => "no note: a decoy's return closes its obligation",
            Class::PotFill => "conserving: SAT out of the repayment pot (the slashed bonds' SAT, taken out of circulation by the slash), at the floor price, never above the pot word",
            Class::PriceMark => "no note",
            Class::WrappedAssetRegister => "no note",
            Class::VaultMerge => "no note: a commitment transition (one custody vault's ledgers are summed into another's, proven against the chain's own pairs)",
            Class::ReserveCost => "no note: a commitment transition (a vault's reserve falls by a public foreign fee, proven against the chain's own pair; nothing is minted or released)",
            Class::VaultKey => "no note: the custody key record moves (a vault takes the key of its members, or retires one it replaced); no value and no ledger word",
            Class::VaultRebalance => "no note: a commitment transition (part of one custody vault's ledgers is carved into its slot, taken by another vault or taken back, each step proven against the chain's own pairs over the slot's one part commitment)",
            Class::OrderPost => "no note",
            Class::DeploymentSignal => "no note",
            Class::ReleaseAttestation => "no note",
            Class::EpochKeyDeal => "no note",
            Class::EpochKeyFraud => "no note: it slashes a bond",
            Class::UnitOpen => "USDm only: the debt note is a USDm mint carrier; the unit note's tag is the unit's terms digest, never the SAT tag",
            Class::UnitClose => "no new value: the unit note dies by an asset bond and the debt burns by a USDm bond-validity carrier whose change is USDm",
            Class::DsolDeploy => "USDm only: the creation price is a USDm BURN by a bond-validity carrier (`deploy_burn_opening`, USDM_ASSET_TAG) whose change is USDm; the manifest and code carry no note",
            Class::DsolCall => "USDm only: the call's fee spend burns USDm by a bond-validity carrier; the publisher-fee note it pays is a USDm note sealed to the publisher (`publisher_fee_seed`)",
            Class::DsolFeeUpdate => "no note: a tighten-only manifest update",
            Class::IonOrder => "no new value: each leg DESTROYS a public amount of one asset (USDm by a bond-validity carrier, a token or a pool's share note by an asset bond carrier) and returns change in that same asset; a SAT-tagged note is spent only as itself",
            Class::IonSettle => "conserving via the pool's row: the payout notes are exactly `ion_pool_tx::settle` of what the pool's pending orders destroyed, recomputed unit for unit at the fold of the block that carries the settlement, and the layer word refuses a batch paying out more USDm than the pool layer took in; the tags are the pool's token, USDm and the pool's own share tag",
            Class::DirEntry => "USDm only: the entry's price is a USDm BURN by a bond-validity carrier (`dir_burn_opening`, USDM_ASSET_TAG) whose change is USDm; the entry itself carries no note",
            Class::DefiOrder => "REFUSED alone (spec §18.12): an order reaches the chain only as a slot of its batch's DefiSlots",
            Class::DefiSlots => "conserving via the audited pool: each order slot SPENDS its owner's exact-amount USDm note into the batch (its nullifier `P(nk, cm)`); each claim slot mints ⌊a·d/n⌋ SAT out of the pool's X at its batch's proven tick, or the order's USDm back on a refund; a cover slot spends nothing (a cover-domain nullifier) and mints 0",
            Class::DefiHandover => "no note: the pool's shares move to a new bonded roster, re-dealt over the same pool (its value unchanged)",
            Class::DefiEarnEpoch => "no note: one audited rate raises each pair's public income index; the income it prices is paid only by withdrawal claims from the backing its merges allocate, never more than the window's fees",
            Class::DefiSettle => "no note: claim LEAVES (`claim_leaf(bc, d, n)`) enter the note set; the SAT they entitle is the pool's X at the audited tick",
            Class::DefiExpire => "no note: refund leaves (`claim_leaf(bc, 1, 1)`) enter the note set; the pool is unchanged",
            Class::DefiClaim => "REFUSED alone (spec §18.12): a claim reaches the chain only as a slot of its batch's DefiSlots, whose fill mints ⌊a·d/n⌋ SAT out of the pool's X — the keyless launch position that split the set-aside's own output (DOOR 2's bound) and what settled orders moved",
        }
    }

    #[must_use]
    pub fn all() -> Vec<Class> {
        (0..=u8::MAX).filter_map(Class::from_byte).collect()
    }

    fn from_byte(b: u8) -> Option<Class> {
        Some(match b {
            1 => Class::OrderFill,
            2 => Class::OrderPost,
            3 => Class::BridgeCredit,
            4 => Class::AssetCreate,
            5 => Class::AssetMint,
            6 => Class::Liquidation,
            7 => Class::WrappedAssetRegister,
            8 => Class::WrappedMint,
            9 => Class::AssetSpend,
            10 => Class::Unbond,
            11 => Class::PegIn,
            12 => Class::PegOut,
            13 => Class::YieldClaim,
            14 => Class::MembershipBond,
            15 => Class::PriceMark,
            16 => Class::Equivocation,
            17 => Class::BondTransition,
            19 => Class::DsolDeploy,
            18 => Class::DsolCall,
            37 => Class::DsolFeeUpdate,
            53 => Class::DirEntry,
            55 => Class::IonOrder,
            56 => Class::IonSettle,
            20 => Class::ReserveTheft,
            21 => Class::PoolDeposit,
            22 => Class::PoolWithdraw,
            23 => Class::SatoshiReward,
            24 => Class::SatBond,
            25 => Class::FinalityVote,
            26 => Class::MinerPayout,
            27 => Class::SatDelegation,
            28 => Class::BondYieldClaim,
            32 => Class::BountyPayout,
            29 => Class::SatSetAside,
            30 => Class::DeploymentSignal,
            31 => Class::ReleaseAttestation,
            40 => Class::EpochKeyDeal,
            42 => Class::EpochKeyFraud,
            33 => Class::TheftRepayment,
            34 => Class::PotFill,
            35 => Class::DecoyBatch,
            36 => Class::DecoyReturn,
            41 => Class::UnitOpen,
            43 => Class::UnitClose,
            44 => Class::DefiOrder,
            45 => Class::DefiSettle,
            46 => Class::DefiExpire,
            47 => Class::DefiClaim,
            48 => Class::DefiHandover,
            49 => Class::DefiSlots,
            57 => Class::DefiEarnEpoch,
            50 => Class::VaultMerge,
            51 => Class::ReserveCost,
            52 => Class::VaultKey,
            54 => Class::VaultRebalance,
            _ => return None,
        })
    }
}

/// Frame a payload as an object of `class`. Every publisher goes through here, so the framing has exactly
/// one implementation and cannot drift between the side that writes and the side that reads.
pub fn frame(class: Class, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + 1 + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(class as u8);
    out.extend_from_slice(payload);
    out
}

/// Read a frame back. `None` for anything that is not one — an ordinary send, a truncated blob, or a class
/// byte this build does not know. Never guesses.
pub fn unframe(blob: &[u8]) -> Option<(Class, &[u8])> {
    if blob.len() < MAGIC.len() + 1 || blob[..MAGIC.len()] != MAGIC {
        return None;
    }
    let class = Class::from_byte(blob[MAGIC.len()])?;
    Some((class, &blob[MAGIC.len() + 1..]))
}

/// ⭐ THE ONE STRICT DECODE every class payload goes through — full consumption, no tolerated tail.
///
/// `postcard::from_bytes` deserializes a PREFIX and ignores trailing bytes, so `encode(x) || junk`
/// decodes to the SAME object while `PqTx::content_id` (blake3 of the whole blob) names a DIFFERENT
/// transaction — the pool's by-id dedup goes blind and ONE object occupies unbounded pool slots, riding
/// a block more than once. That is the wire-malleability forgery the 2026-09-06 red team confirmed at
/// EVERY class decoder. This helper is the shared root fix: it decodes and demands the payload is
/// EXACTLY one object, so a class decoder cannot re-introduce the prefix-tolerant shape — a sixth
/// decoder written tomorrow either calls this or repeats the hole visibly in review.
///
/// ROOT-LAYER: the decode primitive itself, under every class arm (`BridgeCreditTx::decode`,
/// `AssetCreateTx::decode`, `AssetMintTx::decode`, `OrderFillTx::decode`, and both `OrderWire` reads) —
/// strictness is PRODUCED here once, never compensated for at a consumer.
/// MEASURED: RED 2026-09-06 — 5 of 5 trailing-byte pins failed (0 passed) with 7 junk bytes appended
/// after each canonical payload; each padded blob decoded to the same object under a different content
/// id. With this helper the remainder must be 0 bytes or the decode refuses.
/// MUST-STAY-GREEN: every `*_with_trailing_bytes_*` pin (chain_object, asset_tx, order_fill_tx),
/// `an_oversized_credit_frame_is_refused_on_node_a_and_node_b`, and every canonical round-trip test in
/// those suites — the exact wire still decodes.
pub fn decode_exact<'a, T: serde::Deserialize<'a>>(bytes: &'a [u8]) -> Option<T> {
    let (value, rest) = postcard::take_from_bytes::<T>(bytes).ok()?;
    if !rest.is_empty() {
        // A tolerated tail is a second encoding of the same object. ONE object, ONE encoding.
        return None;
    }
    Some(value)
}

/// ⭐⭐⭐ THE NOTES A FRAMED OBJECT ITSELF JUSTIFIES — the per-class note list of the per-note-validity
/// binding (2026-09-06, lane B). ONE place names, for every class, exactly which sealed note payloads an
/// admitted object creates; everything else an object's transaction claims to carry is a forgery.
///
/// `None` = the blob is not a decodable framed object (an unframed send is not judged here — its own ZK
/// carrier gate is its law, and today that carrier binds value conservation but NOT the output note
/// commitments, so the send-side binding is a named prover-lane follow-up in the module residual below).
/// A class that creates no block-carried note (a creation, a resting offer) answers an EMPTY list — a
/// real answer, not a skip: a wrapper claiming notes for such an object is refused by the binding.
pub fn carried_note_payloads(blob: &[u8]) -> Option<Vec<Vec<u8>>> {
    let (class, payload) = unframe(blob)?;
    Some(match class {
        Class::OrderFill => {
            crate::order_fill_tx::OrderFillTx::decode(payload)?.notes.to_vec()
        }
        // A resting offer creates NO block-carried note — its maker payout is created by the FILL.
        Class::OrderPost => {
            decode_exact::<crate::order_book::OrderWire>(payload)?;
            Vec::new()
        }
        Class::BridgeCredit => {
            vec![crate::bridge_credit_tx::BridgeCreditTx::decode(payload)?.note]
        }
        Class::AssetMint => vec![crate::asset_tx::AssetMintTx::decode(payload)?.note],
        Class::SatoshiReward => vec![crate::satoshi::SatoshiRewardTx::decode(payload)?.note],
        // §BR-15: an order's burn change; a settlement's claim leaves and an expiry's refund leaves (each a note slot holding the
        // leaf); a claim's minted note.
        // §18.12: an order slot carries no note (its USDm leaves into the pool); a lone one is refused at every door
        Class::DefiOrder => {
            crate::defi_batch::DefiOrderTx::decode(payload)?;
            Vec::new()
        }
        // §18.12: a batch's slots carry each claim's minted note, in slot order
        Class::DefiSlots => crate::defi_batch::DefiSlotsTx::decode(payload)?.notes(),
        Class::DefiSettle => crate::defi_batch::DefiSettleTx::decode(payload)?.leaves.iter().map(crate::defi_batch::leaf_note_payload).collect(),
        Class::DefiExpire => crate::defi_batch::DefiExpireTx::decode(payload)?.leaves.iter().map(crate::defi_batch::leaf_note_payload).collect(),
        Class::DefiClaim => vec![crate::defi_batch::DefiClaimTx::decode(payload)?.note],
        // §BR-15 §18.11: a handover moves shares, never a note
        Class::DefiHandover => {
            crate::defi_handover::DefiHandoverTx::decode(payload)?;
            Vec::new()
        }
        // ⭐ Earn step 3: an EarnEpoch raises public indices, never a note
        Class::DefiEarnEpoch => {
            crate::defi_batch::DefiEarnEpochTx::decode(payload)?;
            Vec::new()
        }
        // §BR-11: the miner-pool payout's note — a receivable USDm note to the producer's own key.
        Class::MinerPayout => vec![crate::miner_payout_tx::MinerPayoutTx::decode(payload)?.note],
        // §BR-3 17.6: the claim's one USDm note.
        Class::BondYieldClaim => vec![crate::bond_yield_claim_tx::BondYieldClaimTx::decode(payload)?.note],
        // §BR-10: the bounty's one USDm note.
        Class::BountyPayout => vec![crate::bounty_payout_tx::BountyPayoutTx::decode(payload)?.note],
        // §BR-13: the set-aside's one recorded note.
        Class::SatSetAside => vec![crate::sat_set_aside::SatSetAsideTx::decode(payload)?.note],
        // §BR-3 17.5 layer 1: a pot fill justifies exactly the SAT bought and the burn's change.
        Class::PotFill => {
            let t = crate::pot_fill_tx::PotFillTx::decode(payload)?;
            vec![t.sat_note, t.change_note]
        }
        // §BR-4 B4-3: a unit close justifies exactly the debt burn's change.
        Class::UnitClose => vec![crate::unit_close_tx::UnitCloseTx::decode(payload)?.change_note],
        // §BR-4 B4-2: a unit open justifies exactly its peg-in's USDm note and the unit note, in that order.
        Class::UnitOpen => {
            let t = crate::unit_open_tx::UnitOpenTx::decode(payload)?;
            let (_h, _pc, _mc, _bs, _a, note, _sealed, _owner_clue) = crate::peg_in_tx::decode(&t.peg_in)?;
            vec![note, t.unit_note]
        }
        // §BR-3 17.3: a conversion justifies exactly its minted note and the burn's change, in the carriers' order.
        Class::SatDelegation => {
            let t = crate::sat_delegation_tx::SatDelegationTx::decode(payload)?;
            let mut v = vec![t.minted_note, t.change_note];
            if !t.yield_note.is_empty() {
                v.push(t.yield_note); // §17.6: the yield note, when the kind pays one
            }
            v
        }
        // SAT bond: ONLY the change is a receivable note — output 0 is the LOCKED bond (returned by an unbond, never recorded).
        Class::SatBond => vec![crate::sat_bond_tx::SatBondTx::decode(payload)?.notes[1].clone()],
        // A TRANSFER's two outputs, in the carrier's own order — the same order the validity carrier
        // welds `out0_cm`/`out1_cm` to, so a wrapper that reorders them binds nothing.
        Class::AssetSpend => crate::asset_tx::AssetSpendTx::decode(payload)?.notes.to_vec(),
        // ⛔ AN UNBOND MINTS NOTHING. The bonded note already rides the block that admitted it
        // (`Block::bond_set`), so this object carries only the AUTHORISATION to return it; a wrapper
        // claiming any note for one is a forgery this binding refuses.
        Class::Unbond => {
            crate::unbond_tx::decode(payload)?;
            Vec::new()
        }
        // ⛔ A SEAT MINTS NOTHING. It carries an authorisation to be counted, never a note; a wrapper
        // claiming any note for one is a forgery this binding refuses.
        Class::MembershipBond => {
            crate::membership_bond_tx::decode(payload)?;
            Vec::new()
        }
        // ⛔ AN EQUIVOCATION MINTS NOTHING. It carries evidence that burns a bond, never a note; a wrapper claiming
        // any note for one is a forgery this binding refuses.
        Class::Equivocation => {
            crate::equivocation_tx::decode(payload)?;
            Vec::new()
        }
        // ⛔ A FINALITY VOTE MINTS NOTHING. It carries one signed (block, height), never a note; a wrapper claiming any
        // note for one is a forgery this binding refuses.
        Class::FinalityVote => {
            crate::finality_vote_tx::decode(payload)?;
            Vec::new()
        }
        // §BR-10: a deployment signal and a release attestation mint nothing; a wrapper claiming a note for one is refused.
        Class::DeploymentSignal => {
            crate::deployment_signal_tx::DeploymentSignalTx::decode(payload)?;
            Vec::new()
        }
        Class::ReleaseAttestation => {
            crate::release_attestation_tx::ReleaseAttestationTx::decode(payload)?;
            Vec::new()
        }
        // §BR-9a: an epoch-key deal mints nothing; a wrapper claiming a note for one is refused.
        Class::EpochKeyDeal => {
            crate::epoch_deal_tx::EpochKeyDealTx::decode(payload)?;
            Vec::new()
        }
        // ⛔ §BR-9a: an epoch-key fraud proof MINTS NOTHING — it slashes a bond.
        Class::EpochKeyFraud => {
            crate::epoch_fraud_tx::decode(payload)?;
            Vec::new()
        }
        // ⛔ A THEFT SLASH MINTS NOTHING. It carries evidence that burns bonds, never a note; a wrapper claiming any note
        // for one is a forgery this binding refuses.
        Class::ReserveTheft => {
            crate::theft_tx::decode(payload)?;
            Vec::new()
        }
        // LIQUIDATION §10: a pool deposit justifies exactly TWO notes — the receipt and the change — the deposit carrier
        // binds both commitments.
        Class::PoolDeposit => {
            let d = crate::pool_tx::decode(payload)?;
            vec![d.receipt, d.change]
        }
        // LIQUIDATION §10.2: a pool withdrawal justifies exactly ONE note — the compounded USDm the receipt carrier binds.
        Class::PoolWithdraw => vec![crate::pool_tx::decode_withdraw(payload)?.out],
        // ⛔ A BOND TRANSITION MINTS NOTHING. It states bonds whose notes ride their own transactions; a wrapper
        // claiming any note for one is a forgery this binding refuses.
        Class::BondTransition => {
            crate::note_transition::BondTransition::decode(payload)?;
            Vec::new()
        }
        // ⭐⭐⭐ A CREATION MINTS NO VALUE AND PLANTS EXACTLY ONE THING: ITS ISSUANCE RIGHT.
        //
        // The right is `H(domain ‖ asset_id)` and `asset_id` is the object's OWN derived id, so every node
        // computes this note from the creation's bytes rather than taking a wrapper's word for it. That is
        // what lets the right be a real unspent note — the mint retires it with the ordinary deletion
        // transition (§AQ) — without opening a lane a creation could use to carry value it did not create.
        //
        // ⛔ A creation carrying ANY OTHER note is refused right here: the comparison is byte-exact.
        // ⭐ §BR-14: AND THE FEE BURN'S CHANGE — the carrier's `out1`, whose commitment `fee_carrier_verifies` binds.
        Class::AssetCreate => {
            // A-F34: a creation WITH its supply carries the change and the supply note (the creator's signature and the
            // mint carrier bind it: `AssetCreateTx::supply_authorised`, asked by `admissible` and at the fold) and plants
            // no right, since its own lane retires the right's tag. The one list: `AssetCreateTx::carried_notes`.
            crate::asset_tx::AssetCreateTx::decode(payload)?.carried_notes()
        }
        Class::DsolDeploy => {
            // §BR-12 L1: the only note a deploy carries is its fee burn's change (the burn itself is destroyed, never a note)
            let d = crate::dsol_deploy_tx::DsolDeployTx::decode(payload)?;
            vec![d.fee.change_note]
        }
        Class::DirEntry => {
            // audit F15: the only note a paid directory entry carries is its fee burn's change
            let t = crate::dir_entry_tx::DirEntryTx::decode(payload)?;
            vec![t.fee.change_note]
        }
        Class::IonOrder => {
            // IonSwap pools: an order carries only its legs' change (what it burns is destroyed, never a note)
            let t = crate::ion_pool_tx::IonOrderTx::decode(payload)?;
            t.legs.into_iter().map(|f| f.change_note).collect()
        }
        Class::IonSettle => {
            // IonSwap pools: the batch's payout notes, which the fold accepts only if they are the ones it recomputes
            let t = crate::ion_pool_tx::IonSettleTx::decode(payload)?;
            t.notes.into_iter().map(|(note, _)| note).collect()
        }
        Class::DsolCall => {
            // §BR-12 L2: the publisher's fee note and the caller's change — both the carrier's own outputs
            let t = crate::dsol_call_tx::DsolCallTx::decode(payload)?;
            vec![t.fee.publisher_note, t.fee.change_note]
        }
        Class::DsolFeeUpdate => {
            crate::dsol_fee_update_tx::DsolFeeUpdateTx::decode(payload)?;
            Vec::new() // moves no value, carries no note
        }
        // A LIQUIDATION creates NO block-carried note, and that empty list is a real answer rather than a
        // skip: it is a commitment RE-MARK — the reserve digest moves down and the circulating digest moves
        // down, both proven in-circuit — so a wrapper claiming any note for one is a forgery the binding
        // refuses. The seized collateral leaves on the foreign chain, not as a note here.
        Class::Liquidation => {
            crate::liquidation_tx::decode(payload)?;
            Vec::new()
        }
        // §BR-3 17.5: a theft repayment is a commitment transition (the reserve books the loss, the supply retires layers):
        // no note, so a wrapper claiming one is a forgery.
        Class::TheftRepayment => {
            crate::theft_repayment_tx::decode(payload)?;
            Vec::new()
        }
        // §BR-8: decoy bookings and returns carry no note (the decoys are custody's own Bitcoin outputs).
        Class::DecoyBatch => {
            crate::decoy_tx::DecoyBatchTx::decode(payload)?;
            Vec::new()
        }
        Class::DecoyReturn => {
            crate::decoy_tx::DecoyReturnTx::decode(payload)?;
            Vec::new()
        }
        // A PRICE MARK mints nothing: it sets what a unit is worth. The empty list is the real answer, so
        // a wrapper claiming any note for one is a forgery `wrapper_binds_object` refuses.
        Class::PriceMark => {
            crate::price_mark_tx::decode(payload)?;
            Vec::new()
        }
        // A REGISTRATION mints nothing: it sets a ratio. The empty list is the real answer, so a wrapper
        // claiming any note for one is a forgery `wrapper_binds_object` refuses.
        Class::WrappedAssetRegister => {
            crate::wrapped_asset_tx::decode(payload)?;
            Vec::new()
        }
        // A VAULT MERGE mints nothing: it sums one vault's ledgers into another's. The empty list is the real answer,
        // so a wrapper claiming any note for one is a forgery `wrapper_binds_object` refuses.
        Class::VaultMerge => {
            crate::vault_merge_tx::decode(payload)?;
            Vec::new()
        }
        // A RESERVE COST mints nothing: it lowers a vault's reserve. No note, so a wrapper claiming one is a forgery.
        Class::ReserveCost => {
            crate::reserve_cost_tx::decode(payload)?;
            Vec::new()
        }
        // A VAULT KEY statement mints nothing and moves no ledger word. No note, so a wrapper claiming one is a forgery.
        Class::VaultKey => {
            crate::vault_key_tx::decode(payload)?;
            Vec::new()
        }
        // A REBALANCE mints nothing: it moves part of one vault's ledgers to another's. No note, so a wrapper
        // claiming one is a forgery `wrapper_binds_object` refuses.
        Class::VaultRebalance => {
            crate::vault_rebalance_tx::decode(payload)?;
            Vec::new()
        }
        // A wrapped mint DOES justify a note — exactly one, its own — so the wrapper's `output_notes`
        // must be byte-exactly that note and nothing more.
        Class::WrappedMint => {
            let (_h, _c, _mc, _a, note, _sealed, _owner_clue) = crate::wrapped_mint_tx::decode(payload)?;
            vec![note]
        }
        // A peg-in justifies EXACTLY ONE note — the note its own mint carrier proves opens to the
        // attested amount — so the wrapper's `output_notes` must be byte-exactly that note and no more.
        Class::PegIn => {
            let (_h, _pc, _mc, _bs, _a, note, _sealed, _owner_clue) = crate::peg_in_tx::decode(payload)?;
            vec![note]
        }
        // A peg-out justifies exactly the redeemer's CHANGE note — the rest of the value is burned.
        Class::PegOut => {
            let (_h, _c, _r, _a, change, _sealed, _owner_clue, _ticket) = crate::peg_out_tx::decode(payload)?;
            vec![change]
        }
        // DB-237: a stake object justifies exactly TWO notes — the principal and the second output (change or reward) —
        // in the order the stake carrier binds them, and nothing else.
        Class::YieldClaim => {
            let d = crate::stake_tx::decode(payload)?;
            vec![d.out0, d.out1]
        }
    })
}

/// ⭐⭐⭐ DB-273 §19 L1 — THE OWNER CLUE RECORDS AN OWNER-NAMED OBJECT CARRIES, read from the OBJECT itself. `Some(records)`
/// for a class whose owner clue rides the object (a bridge credit binds it in its attested message; a peg-in and a
/// wrapped mint in the recipient the quorum signs, which `decode` re-opens; a peg-out's CHANGE in the v4 statement's
/// `change_owner`, §19.3 L2; an asset mint in the creator-signed `asset_mint_msg` v2, §19.6 L3); `None` for every other class, whose clues ride `PqTx::note_clues` under DB-330's rule.
/// ROOT-LAYER: the object's bytes are what its content id and its signatures cover; `PqTx::note_clues` is covered by
/// neither, so a relay could strip or replace the sidecar and the note would land UNFILED for its owner (DB-351's class).
/// MEASURED: READ — `carried_clue_records` filed whatever the sidecar held for every class; after → the §19 L1 pin
/// (a relay-stripped sidecar still files the object's own record on a second node).
/// MUST-STAY-GREEN: the DB-330 staging pins (a transfer's clues still come from its sidecar), §17a's credit pins.
/// cons: none — 0 B added to any object or block (the record is read from bytes the object already carries); one
/// decode per framed owner-named tx at staging, the same O(1) decode `admissible` already runs on it.
pub fn object_owner_clue_records(blob: &[u8]) -> Option<Vec<([u8; 32], Vec<u8>)>> {
    let (class, payload) = unframe(blob)?;
    let (note, clue) = match class {
        Class::BridgeCredit => {
            let c = crate::bridge_credit_tx::BridgeCreditTx::decode(payload)?;
            (c.note, c.owner_clue)
        }
        Class::PegIn => {
            let (_h, _pc, _mc, _bs, _a, note, _sealed, owner_clue) = crate::peg_in_tx::decode(payload)?;
            (note, owner_clue)
        }
        Class::WrappedMint => {
            let (_h, _c, _mc, _a, note, _sealed, owner_clue) = crate::wrapped_mint_tx::decode(payload)?;
            (note, owner_clue)
        }
        // DB-273 §19.6 L3: an asset mint's ONE note, under the creator's signature (`asset_mint_msg` v2 binds the digest).
        Class::AssetMint => {
            let m = crate::asset_tx::AssetMintTx::decode(payload)?;
            (m.note, m.owner_clue)
        }
        // §BR-14: a creation's fee-burn CHANGE, filed under the clue the object carries (the issue right is nobody's balance).
        Class::AssetCreate => {
            let c = crate::asset_tx::AssetCreateTx::decode(payload)?;
            // A-F34: a creation with its supply files TWO notes: the fee's change, and the supply under the clue the
            // creator signed (`asset_mint_msg` binds its digest)
            if let Some(s) = c.supply {
                let change = <[u8; 32]>::try_from(c.fee.change_note.get(..32)?).ok()?;
                let minted = <[u8; 32]>::try_from(s.note.get(..32)?).ok()?;
                return Some(vec![(change, c.fee.change_clue), (minted, s.owner_clue)]);
            }
            (c.fee.change_note, c.fee.change_clue)
        }
        Class::DsolDeploy => {
            let d = crate::dsol_deploy_tx::DsolDeployTx::decode(payload)?;
            (d.fee.change_note, d.fee.change_clue)
        }
        Class::DirEntry => {
            let t = crate::dir_entry_tx::DirEntryTx::decode(payload)?;
            (t.fee.change_note, t.fee.change_clue)
        }
        // IonSwap pools: each leg's change under its own clue (the leg's carrier binds the change commitment).
        Class::IonOrder => {
            let t = crate::ion_pool_tx::IonOrderTx::decode(payload)?;
            let mut out = Vec::with_capacity(t.legs.len());
            for f in t.legs {
                out.push((<[u8; 32]>::try_from(f.change_note.get(..32)?).ok()?, f.change_clue));
            }
            return Some(out);
        }
        // IonSwap pools: every payout note under the locator clue of the locator the settlement carries for it (the fold
        // accepts the settlement only if each locator is the one its pending order stated for that asset, so a former
        // cannot file a payout for anyone else).
        Class::IonSettle => {
            let t = crate::ion_pool_tx::IonSettleTx::decode(payload)?;
            let mut out = Vec::with_capacity(t.notes.len());
            for (note, locator) in t.notes {
                let clue = crate::ion_pool_tx::ion_locator_clue(&locator);
                out.push((<[u8; 32]>::try_from(note.get(..32)?).ok()?, clue));
            }
            return Some(out);
        }
        Class::DsolCall => {
            // the publisher finds its note from the chain's public words (cid, tx hash); only the change carries a clue
            let t = crate::dsol_call_tx::DsolCallTx::decode(payload)?;
            (t.fee.change_note, t.fee.change_clue)
        }
        // §BR-15: the order's change under its owner's clue; the claim's note under its owner's clue (both signed by the
        // object's own proof binding — the burn carrier binds `change_cm`, the mint carrier the note).
        // §18.12: every claim slot's note under its owner's clue (a cover's clue is noise no wallet opens)
        Class::DefiSlots => {
            let t = crate::defi_batch::DefiSlotsTx::decode(payload)?;
            let mut out = Vec::with_capacity(t.claims.len());
            for c in t.claims {
                let cm = <[u8; 32]>::try_from(c.note.get(..32)?).ok()?;
                out.push((cm, c.owner_clue));
            }
            return Some(out);
        }
        Class::DefiClaim => {
            let t = crate::defi_batch::DefiClaimTx::decode(payload)?;
            (t.note, t.owner_clue)
        }
        // SATOSHI: the miner's reward note, filed under the clue the object carries.
        Class::SatoshiReward => {
            let r = crate::satoshi::SatoshiRewardTx::decode(payload)?;
            (r.note, r.owner_clue)
        }
        // §BR-11: the payout note, filed under its clue like the reward beside it.
        Class::MinerPayout => {
            let p = crate::miner_payout_tx::MinerPayoutTx::decode(payload)?;
            (p.note, p.owner_clue)
        }
        // §BR-3 17.6: the claim's note under its clue (signed into the claim's statement).
        Class::BondYieldClaim => {
            let t = crate::bond_yield_claim_tx::BondYieldClaimTx::decode(payload)?;
            (t.note, t.owner_clue)
        }
        // §BR-10: the bounty's note under its clue (signed into the bounty's statement).
        Class::BountyPayout => {
            let t = crate::bounty_payout_tx::BountyPayoutTx::decode(payload)?;
            (t.note, t.owner_clue)
        }
        // §BR-13: the set-aside note under its clue (part of the canonical bytes).
        Class::SatSetAside => {
            let t = crate::sat_set_aside::SatSetAsideTx::decode(payload)?;
            (t.note, t.owner_clue)
        }
        // SATOSHI §6: a bond's CHANGE note, filed under its clue (the locked note is nobody's balance).
        Class::SatBond => {
            let t = crate::sat_bond_tx::SatBondTx::decode(payload)?;
            (t.notes[1].clone(), t.owner_clue)
        }
        // DB-273 §19.6 L3: an asset transfer's TWO outputs, each with its own clue, in the carrier's order. Bound by the
        // object's bytes (the transfer class's named residual until the validity carrier binds `owner_clues_digest`).
        Class::AssetSpend => {
            let t = crate::asset_tx::AssetSpendTx::decode(payload)?;
            let mut out = Vec::with_capacity(crate::asset_tx::ASSET_SPEND_OUTPUTS);
            for (note, clue) in t.notes.iter().zip(t.owner_clues) {
                let cm = <[u8; 32]>::try_from(note.get(..32)?).ok()?;
                out.push((cm, clue));
            }
            return Some(out);
        }
        // DB-273 §19.6 L3: a fill's THREE notes (maker payout, taker payout, taker change), each with its own clue. Slot 0
        // is the MAKER's, copied by the fill door from the order the maker posted; slots 1–2 are the taker's. This
        // subsumes DB-330's fill arm (the taker's two from the relay-mutable sidecar).
        Class::OrderFill => {
            let f = crate::order_fill_tx::OrderFillTx::decode(payload)?;
            let mut out = Vec::with_capacity(3);
            for (note, clue) in f.notes.iter().zip(f.owner_clues) {
                let cm = <[u8; 32]>::try_from(note.get(..32)?).ok()?;
                out.push((cm, clue));
            }
            return Some(out);
        }
        // LIQUIDATION §10.2: a pool withdrawal's ONE note with its clue.
        Class::PoolWithdraw => {
            let d = crate::pool_tx::decode_withdraw(payload)?;
            let cm = <[u8; 32]>::try_from(d.out.get(..32)?).ok()?;
            return Some(vec![(cm, d.owner_clues.into_iter().next()?)]);
        }
        // LIQUIDATION §10: a pool deposit's TWO notes (receipt, change), each with its own clue, bound by the object's bytes.
        Class::PoolDeposit => {
            let d = crate::pool_tx::decode(payload)?;
            let mut out = Vec::with_capacity(crate::pool_tx::POOL_DEPOSIT_NOTE_COUNT);
            for (note, clue) in [d.receipt, d.change].into_iter().zip(d.owner_clues) {
                let cm = <[u8; 32]>::try_from(note.get(..32)?).ok()?;
                out.push((cm, clue));
            }
            return Some(out);
        }
        // DB-273 §19.3 L2: a yield claim's THREE notes, each with its own clue, in (principal, change, reward) order. Bound
        // by the object's bytes, not by a signature (carrier-authorized — the transfer class's named residual).
        Class::YieldClaim => {
            let d = crate::stake_tx::decode(payload)?;
            let mut out = Vec::with_capacity(crate::stake_tx::STAKE_NOTE_COUNT);
            for (note, clue) in [d.out0, d.out1].into_iter().zip(d.owner_clues) {
                let cm = <[u8; 32]>::try_from(note.get(..32)?).ok()?;
                out.push((cm, clue));
            }
            return Some(out);
        }
        // §BR-3 17.5 layer 1: the SAT bought and the change, each under its own clue.
        Class::PotFill => {
            let t = crate::pot_fill_tx::PotFillTx::decode(payload)?;
            let mut out = Vec::with_capacity(2);
            for (note, clue) in [(t.sat_note, t.sat_clue), (t.change_note, t.change_clue)] {
                let cm = <[u8; 32]>::try_from(note.get(..32)?).ok()?;
                out.push((cm, clue));
            }
            return Some(out);
        }
        // §BR-4 B4-3: the change under its own clue.
        Class::UnitClose => {
            let t = crate::unit_close_tx::UnitCloseTx::decode(payload)?;
            let cm = <[u8; 32]>::try_from(t.change_note.get(..32)?).ok()?;
            return Some(vec![(cm, t.change_clue)]);
        }
        // §BR-4 B4-2: the USDm note under the peg-in's signed clue, the unit note under its own.
        Class::UnitOpen => {
            let t = crate::unit_open_tx::UnitOpenTx::decode(payload)?;
            let (_h, _pc, _mc, _bs, _a, note, _sealed, owner_clue) = crate::peg_in_tx::decode(&t.peg_in)?;
            let mut out = Vec::with_capacity(2);
            for (n, clue) in [(note, owner_clue), (t.unit_note, t.unit_clue)] {
                let cm = <[u8; 32]>::try_from(n.get(..32)?).ok()?;
                out.push((cm, clue));
            }
            return Some(out);
        }
        // §BR-3 17.3: the minted note and the change, each under its own clue.
        Class::SatDelegation => {
            let t = crate::sat_delegation_tx::SatDelegationTx::decode(payload)?;
            let mut out = Vec::with_capacity(3);
            for (note, clue) in [(t.minted_note, t.minted_clue), (t.change_note, t.change_clue), (t.yield_note, t.yield_clue)] {
                if note.is_empty() {
                    continue; // §17.6: no yield note when the kind pays none
                }
                let cm = <[u8; 32]>::try_from(note.get(..32)?).ok()?;
                out.push((cm, clue));
            }
            return Some(out);
        }
        // DB-273 §19.3 L2: the CHANGE note's clue, under the quorum's v4 statement (`PegOutHeader::change_owner`).
        Class::PegOut => {
            let (_h, _c, _r, _a, change, _sealed, owner_clue, _ticket) = crate::peg_out_tx::decode(payload)?;
            if change.is_empty() {
                return Some(Vec::new()); // no change note, no owner (decode refuses a clue with nothing to own)
            }
            (change, owner_clue)
        }
        _ => return None,
    };
    let cm = <[u8; 32]>::try_from(note.get(..32)?).ok()?;
    Some(if clue.is_empty() { Vec::new() } else { vec![(cm, clue)] })
}

/// ⭐⭐⭐ DB-224 — THE WIDTH OF A NOTE REFERENCE: `cm(32) ‖ slot(32)`.
///
/// `cm` is `note[..32]`, the commitment every rule on this chain reads of a note (through
/// `spend_frontier::note_cm_of`); `slot` is `Hash32::hash(note)`, the value the block's constant-width
/// note carrier ([`crate::block::Block::note_commitments`]) stores for that note. A reference therefore
/// states what the object's rules bind AND binds the whole payload by preimage resistance — and it is
/// not the payload, which is the only secret input of `cover::block_cover_secret`.
pub const NOTE_REF_BYTES: usize = 64;

/// ⭐⭐⭐ DB-224 — A NOTE'S REFERENCE. A full sealed payload (`PQ_NOTE_BYTES`) becomes `cm ‖ slot`; a value
/// that is already a reference is returned unchanged, so the carriage is idempotent. Anything else is not
/// a note and has no reference (`None`): a carriage built over it would bind bytes no rule ever read.
#[must_use]
pub fn note_ref(note: &[u8]) -> Option<Vec<u8>> {
    if note.len() == NOTE_REF_BYTES {
        return Some(note.to_vec());
    }
    if note.len() != crate::cover::PQ_NOTE_BYTES {
        return None;
    }
    let mut r = Vec::with_capacity(NOTE_REF_BYTES);
    r.extend_from_slice(&note[..crate::spend_frontier::NOTE_CM_BYTES]);
    r.extend_from_slice(crate::hash::Hash32::hash(note).as_bytes());
    Some(r)
}

/// ⭐⭐⭐ DB-224 — THE CARRIAGE FORM OF A FRAMED OBJECT: the form [`crate::block::Block::credit_set`]
/// carries on the wire.
///
/// ⛔⛔⛔ WHY NOT THE OBJECT ITSELF. Since DB-165 the set does not travel, so a peer rebuilt it from its OWN
/// mempool and a framed object applied only where its tx happened to be pooled in time (DB-224, measured:
/// the producer held a price mark, the peer grafted the block and held none). Putting the objects back
/// verbatim would put NOTE PAYLOADS back on the block wire — and real note bytes are the only secret input
/// of `cover::block_cover_secret`, the DB-165 regeneration attack. So the object travels with every note
/// payload replaced by its [`note_ref`]: `cm` is all any class rule reads of a note (the tally messages,
/// the mint / spend / fill carriers and the creator signature all bind `note_cm_of(note)`), and `slot`
/// binds the payload it stands for, which reaches a node the way every note does (its pool, or the DA
/// record). Note-free classes are carried unchanged.
///
/// The carriage is the SAME class under the SAME codec — every decoder accepts a 64-byte note — so every
/// door judges it with the rule it already has. Idempotent: the carriage of a carriage is itself.
///
/// `None` = not a decodable framed object, or a note field that is neither a whole payload nor a
/// reference. Fail-closed: such an object cannot be carried, and the notes it would have justified are
/// refused on every node.
#[must_use]
/// ⛔ §SIMMEM G13b (lane b 2026-10-23) — ONE OBJECT, ONE LANE. A finality vote, an equivocation proof and a reserve-theft
/// proof name no note and own no nullifier, and their one reader is the BOND lane (`Block::bond_set`: the G2 finality
/// tally, the slashing doors). Every credit-lane reader acts only on a note an object names, a nullifier it owns, or a
/// class the fold or the book applies — none of which these are — so a credit-lane copy applied nothing and was a second
/// encoding of one consensus object: ~5 KB of ML-DSA bytes per vote per block, held by every node until the fold (MEASURED
/// scratchpad/verify/simmem-g13fix2.out: at 10 nodes `unfolded_blocks` held credit_set 416.7 MB beside bond_set 419.0 MB).
/// The producer's credit carriage (`Node::carriage_carried_against`) and the peer's structural rule
/// (`consensus::credit_set_is_carried_with_its_subjects`) read this ONE predicate, so an honest block always passes.
/// (Unbond and MembershipBond also ride the bond lane but OWN a one-shot right nullifier the credit lane's respend contest
/// and DB-388 lane check read, so they keep both lanes.)
#[must_use]
pub fn rides_the_bond_lane_alone(blob: &[u8]) -> bool {
    matches!(
        unframe(blob).map(|(c, _)| c),
        Some(Class::FinalityVote | Class::Equivocation | Class::ReserveTheft | Class::EpochKeyFraud)
    )
}

pub fn carriage_of(blob: &[u8]) -> Option<Vec<u8>> {
    let (class, payload) = unframe(blob)?;
    // A PegOut with no change carries an EMPTY change note (`carried_note_payloads` returns it as such,
    // and the wrapper binding demands empty `output_notes` for it); empty stays empty.
    let ref_or_empty = |n: &[u8]| -> Option<Vec<u8>> {
        if n.is_empty() {
            Some(Vec::new())
        } else {
            note_ref(n)
        }
    };
    let body: Vec<u8> = match class {
        Class::OrderFill => {
            let mut f = crate::order_fill_tx::OrderFillTx::decode(payload)?;
            for n in f.notes.iter_mut() {
                *n = note_ref(n)?;
            }
            postcard::to_allocvec(&f).ok()?
        }
        Class::BridgeCredit => {
            let mut c = crate::bridge_credit_tx::BridgeCreditTx::decode(payload)?;
            c.note = note_ref(&c.note)?;
            postcard::to_allocvec(&c).ok()?
        }
        Class::AssetMint => {
            let mut m = crate::asset_tx::AssetMintTx::decode(payload)?;
            m.note = note_ref(&m.note)?;
            postcard::to_allocvec(&m).ok()?
        }
        // §BR-13: the set-aside's note becomes a reference
        Class::SatSetAside => {
            let mut t = crate::sat_set_aside::SatSetAsideTx::decode(payload)?;
            t.note = note_ref(&t.note)?;
            postcard::to_allocvec(&t).ok()?
        }
        // §BR-3 17.6: the claim's note becomes a reference
        Class::BondYieldClaim => {
            let mut t = crate::bond_yield_claim_tx::BondYieldClaimTx::decode(payload)?;
            t.note = note_ref(&t.note)?;
            postcard::to_allocvec(&t).ok()?
        }
        // §BR-10: the bounty's note becomes a reference
        Class::BountyPayout => {
            let mut t = crate::bounty_payout_tx::BountyPayoutTx::decode(payload)?;
            t.note = note_ref(&t.note)?;
            postcard::to_allocvec(&t).ok()?
        }
        // §BR-4 B4-3: the change becomes a reference
        Class::UnitClose => {
            let mut t = crate::unit_close_tx::UnitCloseTx::decode(payload)?;
            t.change_note = note_ref(&t.change_note)?;
            postcard::to_allocvec(&t).ok()?
        }
        // §BR-4 B4-2: both carried notes become references (the peg-in's inside its own payload)
        Class::UnitOpen => {
            let mut t = crate::unit_open_tx::UnitOpenTx::decode(payload)?;
            let (h, pc, mc, bs, pairs, note, sealed, owner_clue) = decode_exact::<crate::peg_in_tx::PegInPayload>(&t.peg_in)?;
            t.peg_in = postcard::to_allocvec(&(h, pc, mc, bs, pairs, note_ref(&note)?, sealed, owner_clue)).ok()?;
            t.unit_note = note_ref(&t.unit_note)?;
            postcard::to_allocvec(&t).ok()?
        }
        // §BR-3 17.5 layer 1: both carried notes become references
        Class::PotFill => {
            let mut t = crate::pot_fill_tx::PotFillTx::decode(payload)?;
            t.sat_note = note_ref(&t.sat_note)?;
            t.change_note = note_ref(&t.change_note)?;
            postcard::to_allocvec(&t).ok()?
        }
        // §BR-3 17.3: both carried notes become references
        Class::SatDelegation => {
            let mut t = crate::sat_delegation_tx::SatDelegationTx::decode(payload)?;
            t.minted_note = note_ref(&t.minted_note)?;
            t.change_note = note_ref(&t.change_note)?;
            if !t.yield_note.is_empty() {
                t.yield_note = note_ref(&t.yield_note)?;
            }
            postcard::to_allocvec(&t).ok()?
        }
        // §BR-14: the creation's one carried note payload is its fee burn's change (the issue right is DERIVED).
        Class::AssetCreate => {
            let mut c = crate::asset_tx::AssetCreateTx::decode(payload)?;
            c.fee.change_note = note_ref(&c.fee.change_note)?;
            // A-F34: the supply note travels by reference too
            if let Some(s) = c.supply.as_mut() {
                s.note = note_ref(&s.note)?;
            }
            postcard::to_allocvec(&c).ok()?
        }
        Class::DsolDeploy => {
            let mut d = crate::dsol_deploy_tx::DsolDeployTx::decode(payload)?;
            d.fee.change_note = note_ref(&d.fee.change_note)?;
            postcard::to_allocvec(&d).ok()?
        }
        Class::DirEntry => {
            let mut t = crate::dir_entry_tx::DirEntryTx::decode(payload)?;
            t.fee.change_note = note_ref(&t.fee.change_note)?;
            postcard::to_allocvec(&t).ok()?
        }
        Class::IonOrder => {
            let mut t = crate::ion_pool_tx::IonOrderTx::decode(payload)?;
            for f in &mut t.legs {
                f.change_note = note_ref(&f.change_note)?;
            }
            postcard::to_allocvec(&t).ok()?
        }
        Class::IonSettle => {
            let mut t = crate::ion_pool_tx::IonSettleTx::decode(payload)?;
            for (note, _) in &mut t.notes {
                *note = note_ref(note)?;
            }
            postcard::to_allocvec(&t).ok()?
        }
        Class::DsolCall => {
            let mut t = crate::dsol_call_tx::DsolCallTx::decode(payload)?;
            t.fee.publisher_note = note_ref(&t.fee.publisher_note)?;
            t.fee.change_note = note_ref(&t.fee.change_note)?;
            postcard::to_allocvec(&t).ok()?
        }
        // ⛔⛔ SATOSHI — THE REWARD TRAVELS WHOLE. It is the one note every block carries, and `output_notes` never rides the wire
        // (DB-165), so as a reference every receiver held every block WITHOUT ITS DATA and fetched its record over the bulk
        // lane. MEASURED 2026-10-05 (lane-harness netsim, 10 parties, 4 s cadence): production record-serve time 56 ms →
        // 225,645 ms, relay p50 1.5 → 6.05 s (past the 4 s floor), and the mesh forked. Whole, the receiver's ONE rehydration
        // door (`Node::rehydrate_block_body`) rebuilds a reward-only block's body itself, checked slot by slot against the
        // committed carrier and as a whole against the header's note root. cons: +1,089 B per block on the wire.
        Class::SatoshiReward => {
            let r = crate::satoshi::SatoshiRewardTx::decode(payload)?;
            postcard::to_allocvec(&r).ok()?
        }
        // §BR-15: every DeFi object rides whole — its proofs and its notes are what its fold applies.
        Class::DefiOrder => postcard::to_allocvec(&crate::defi_batch::DefiOrderTx::decode(payload)?).ok()?,
        Class::DefiSettle => postcard::to_allocvec(&crate::defi_batch::DefiSettleTx::decode(payload)?).ok()?,
        Class::DefiExpire => postcard::to_allocvec(&crate::defi_batch::DefiExpireTx::decode(payload)?).ok()?,
        Class::DefiClaim => postcard::to_allocvec(&crate::defi_batch::DefiClaimTx::decode(payload)?).ok()?,
        Class::DefiSlots => postcard::to_allocvec(&crate::defi_batch::DefiSlotsTx::decode(payload)?).ok()?,
        Class::DefiHandover => postcard::to_allocvec(&crate::defi_handover::DefiHandoverTx::decode(payload)?).ok()?,
        Class::DefiEarnEpoch => postcard::to_allocvec(&crate::defi_batch::DefiEarnEpochTx::decode(payload)?).ok()?,
        // §BR-11: the payout rides whole, exactly as the reward does (the fold recomputes its commitment from these bytes).
        Class::MinerPayout => {
            let p = crate::miner_payout_tx::MinerPayoutTx::decode(payload)?;
            postcard::to_allocvec(&p).ok()?
        }
        // ⛔ SATOSHI — ONLY THE CHANGE NOTE becomes a reference: it rides `output_notes` (`carried_note_payloads`). The LOCKED
        // note rides nowhere else, and the fold applies THIS form (`objects_decide_at_fold` reads `body.credit_set`), so a
        // reference here made every node lock 64 bytes — an unbond would return nothing spendable. MEASURED by reading
        // 2026-10-05 (building §9); pinned by `a_sat_bonds_locked_note_is_held_whole…`. cons: +1,089 B per SAT bond in the set.
        Class::SatBond => {
            let mut t = crate::sat_bond_tx::SatBondTx::decode(payload)?;
            t.notes[1] = note_ref(&t.notes[1])?;
            postcard::to_allocvec(&t).ok()?
        }
        Class::AssetSpend => {
            let mut t = crate::asset_tx::AssetSpendTx::decode(payload)?;
            for n in t.notes.iter_mut() {
                *n = note_ref(n)?;
            }
            postcard::to_allocvec(&t).ok()?
        }
        // The tuple classes re-encode their OWN payload type — the exact type their decoder reads — after
        // that decoder has judged the bounds, so no field is reinterpreted on the way through.
        Class::WrappedMint => {
            crate::wrapped_mint_tx::decode(payload)?;
            // DB-273 §17b: the owner clue rides the carriage unchanged (the signed recipient commits to it).
            let (h, c, mc, pairs, note, sealed, owner_clue) =
                decode_exact::<crate::wrapped_mint_tx::WrappedMintPayload>(payload)?;
            postcard::to_allocvec(&(h, c, mc, pairs, note_ref(&note)?, sealed, owner_clue)).ok()?
        }
        Class::PegIn => {
            crate::peg_in_tx::decode(payload)?;
            // DB-273 §17b: the owner clue rides the carriage unchanged (it is what the signed recipient commits to).
            let (h, pc, mc, bs, pairs, note, sealed, owner_clue) =
                decode_exact::<crate::peg_in_tx::PegInPayload>(payload)?;
            postcard::to_allocvec(&(h, pc, mc, bs, pairs, note_ref(&note)?, sealed, owner_clue)).ok()?
        }
        Class::PegOut => {
            crate::peg_out_tx::decode(payload)?;
            let (h, c, rc, pairs, change, sealed, owner_clue, ticket) =
                decode_exact::<crate::peg_out_tx::PegOutPayload>(payload)?;
            postcard::to_allocvec(&(h, c, rc, pairs, ref_or_empty(&change)?, sealed, owner_clue, ticket)).ok()?
        }
        Class::PoolWithdraw => {
            let d = crate::pool_tx::decode_withdraw(payload)?;
            postcard::to_allocvec(&(
                d.h,
                d.receipt_carrier,
                d.bridge_carrier,
                d.withdraw_carrier,
                d.transition_carrier,
                d.membership_carrier,
                d.membership_tip,
                note_ref(&d.out)?,
                d.owner_clues,
                d.sealed,
                d.gain_sealed,
            ))
            .ok()?
        }
        Class::PoolDeposit => {
            let d = crate::pool_tx::decode(payload)?;
            postcard::to_allocvec(&(
                d.h,
                d.deposit_carrier,
                d.snapshot_carrier,
                d.transition_carrier,
                d.membership_carrier,
                d.membership_tip,
                note_ref(&d.receipt)?,
                note_ref(&d.change)?,
                d.owner_clues,
                d.sealed,
            ))
            .ok()?
        }
        Class::YieldClaim => {
            let d = crate::stake_tx::decode(payload)?;
            postcard::to_allocvec(&(
                d.h,
                d.stake_carrier,
                d.supply_carrier,
                d.membership_carrier,
                d.membership_tip,
                note_ref(&d.out0)?,
                note_ref(&d.out1)?,
                d.owner_clues,
                d.sealed,
            ))
            .ok()?
        }
        // No note field: the object is its own carriage once its class decodes it.
        Class::OrderPost
        | Class::DsolFeeUpdate // §BR-12 L3: a signed manifest change, no note
        | Class::Liquidation
        | Class::TheftRepayment
        | Class::DecoyBatch
        | Class::DecoyReturn
        | Class::WrappedAssetRegister
        | Class::VaultMerge
        | Class::ReserveCost
        | Class::VaultKey
        | Class::VaultRebalance
        | Class::Unbond
        | Class::MembershipBond
        | Class::Equivocation
        | Class::FinalityVote
        | Class::ReserveTheft
        // §BR-9a: an epoch-key fraud proof carries no note
        | Class::EpochKeyFraud
        | Class::BondTransition
        | Class::PriceMark
        // §BR-10: a deployment signal and a release attestation carry no note
        | Class::DeploymentSignal
        | Class::ReleaseAttestation
        // §BR-9a: an epoch-key deal carries no note
        | Class::EpochKeyDeal => {
            carried_note_payloads(blob)?;
            return Some(blob.to_vec());
        }
    };
    let out = frame(class, &body);
    // The carriage must itself be a well-formed object of its class, or no door could judge it.
    carried_note_payloads(&out)?;
    Some(out)
}

/// ⭐⭐⭐ DB-224 — THE PER-ENTRY BOUND ON A CARRIED OBJECT (charter §9.6 q5, bounded work). A carriage is
/// never larger than the transaction it carries, and a transaction's weight IS its blob length, capped by
/// the ≤1.8 MB proof-pillar bound — so that one named number bounds each entry, and
/// `block::credit_set_iter` bounds the count at `BLOCK_FIXED_TX_COUNT`. Both are refused at the door
/// (`consensus::credit_set_is_carried_with_its_subjects`), before any class decoder or verifier runs.
pub const MAX_CARRIAGE_ENTRY_BYTES: usize = crate::params::MAX_TX_WEIGHT_BYTES as usize;

/// ⭐⭐⭐ DB-224 — IS THIS BLOB ALREADY IN CARRIAGE FORM? The consensus rule for every entry of a travelling
/// credit set: an entry must be its own carriage, so a real note payload can never ride the block wire —
/// by construction of the block, not by the producer's courtesy. An entry over the per-entry bound is not
/// a carriage either: it is refused on its length alone, before it is decoded.
#[must_use]
pub fn is_carriage(blob: &[u8]) -> bool {
    blob.len() <= MAX_CARRIAGE_ENTRY_BYTES && carriage_of(blob).is_some_and(|c| c == blob)
}

/// ⭐⭐⭐ DB-224 — THE NOTES A CARRIED OBJECT NAMES, as `(cm, slot)` pairs: the references its carriage
/// holds, plus the reference of any note the class DERIVES (a creation's issue right). This is what the
/// §BA graft door justifies against and what the block's own note carrier must contain (the subject rule).
/// An empty PegOut change names nothing. `None` = not a decodable object or a malformed note field.
#[must_use]
pub fn carriage_note_refs(blob: &[u8]) -> Option<Vec<([u8; 32], [u8; 32])>> {
    let notes = carried_note_payloads(blob)?;
    let mut out = Vec::with_capacity(notes.len());
    for n in notes {
        if n.is_empty() {
            continue;
        }
        let r = note_ref(&n)?;
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&r[..32]);
        let mut slot = [0u8; 32];
        slot.copy_from_slice(&r[32..]);
        out.push((cm, slot));
    }
    Some(out)
}

/// ⭐⭐⭐ THE CARRIAGE IS NOT THE OBJECT — the per-note-validity binding between a transaction WRAPPER
/// and the framed object it carries. RED-measured 2026-09-06 (lane B): `admissible` judges `PqTx::blob`,
/// but assembly and the graft fold carry `PqTx::output_notes` — and NOTHING bound the two. A
/// validly-framed credit blob under a wrapper whose `output_notes` were substituted (or extended with a
/// naked extra chunk) was ADMITTED at `ingest_tx` and RECORDED+FOLDED at graft on an honest peer
/// (`a_credit_wrapper_carrying_notes_the_object_does_not_justify_…` and
/// `a_rogue_producers_injected_chunk_credits_nothing_…`, both RED before this function existed): any
/// submitter — gossip or RPC, no modified producer needed — minted arbitrary sealed value on every
/// honest node.
///
/// THE RULE: for a framed object the wrapper's `output_notes` must be BYTE-EXACTLY the concatenation of
/// the object's own justified notes ([`carried_note_payloads`]), in the object's own order; the wrapper
/// must carry no bond or stake bytes (no class justifies a divert), and no nullifiers unless the class
/// itself burns (only [`Class::OrderFill`] does — its wrapper carries the node-padded burn lane, which is
/// deliberately not byte-derivable from the object; see the residual note in the module doc). An
/// unframed blob passes through: a send is judged by its own carrier gate, exactly as at `admissible`.
/// A framed blob that does not decode binds nothing and is refused — `admissible` refuses it too, so the
/// two doors agree.
///
/// ROOT-LAYER: this function is the ONE implementation, asked at `Node::ingest_tx` (both admission
/// doors), at note assembly (`block_spendable_note_blobs`), and at the graft door
/// (`apply_grafted_block_carry`), so the seams can never drift on what "bound" means.
/// MUST-STAY-GREEN: every honest publisher round-trip in this module's tests and the two lane-B pins
/// named above.
/// ⛔⛔⛔ DB-278 — THE NULLIFIERS AN OBJECT RETIRES THAT ARE DERIVABLE FROM ITS OWN BYTES: a peg-out's burned USDm note, a
/// yield claim's stake, a mint's issuance right, a transfer's burn. ONE definition read by BOTH doors — the pool door
/// ([`wrapper_binds_object`]: the WRAPPER's lane must carry them) and the graft door (`Node::graft_admitted_notes`:
/// the BLOCK's lane must carry them, or the object justifies nothing). MEASURED 2026-09-27 (DB-278 pin): the rule
/// lived only in the pool door, so a producer that skipped its own door laid a mint whose block never retired the
/// issuance right, and a peer that never pooled the tx credited it from the credit-set copy — the right stayed
/// unspent and the creator re-issued.
///
/// `None` for a framed blob of such a class that does not decode (fail-closed at both doors); `Some(empty)` for a
/// class that retires nothing derivable from its bytes.
///
/// ⛔⛔⛔ THE THIRD READER IS DB-358's `Node::respend_items`: an object with own nullifiers is a respend ITEM, so two
/// objects retiring one tag in sibling blocks meet at the fold and the later one's outputs are revoked. A class missing
/// here is invisible to that rule.
pub fn object_own_nullifiers(blob: &[u8]) -> Option<Vec<[u8; 32]>> {
    let (class, payload) = unframe(blob)?;
    Some(match class {
        // ⛔⛔⛔ A FILL RETIRES TWO NULLIFIERS DERIVABLE FROM ITS OWN BYTES: the maker's lot and the taker's spend
        // (`OrderFillTx::nullifier_tags`). Only the cover padding AROUND them is node-chosen.
        // This arm was missing, with the comment "a fill's lane is node-padded, and the object cannot name it". So no
        // fill was a DB-358 item, and two fills of one lot in sibling blocks both kept their outputs.
        // MEASURED 2026-09-30 08:43 (`db358_two_fills_of_one_lot_in_sibling_blocks_pay_the_lot_exactly_once_on_both_
        // parties`, RED): BOTH takers were paid on BOTH parties. The maker's ONE lot paid out twice — the 2026-09-03
        // class, through the concurrent-block path.
        // The pool door already required these tags (the publisher pads `nullifier_tags()` into the wrapper's lane),
        // and so did the graft door (a block's lane carries both burns). Neither door changes behaviour for an honest
        // fill.
        Class::OrderFill => crate::order_fill_tx::OrderFillTx::decode(payload)?
            .nullifier_tags()
            .into_iter()
            .map(|h| h.0)
            .collect(),
        // THE BURN MUST TRAVEL: a peg-out whose USDm nullifier is absent from the lane releases reserve against a
        // note every peer still holds unspent.
        Class::PegOut => vec![crate::peg_out_tx::decode(payload)?.0.usdm_nullifier],
        // The stake nullifier retires everywhere or the same stake harvests once per node.
        Class::YieldClaim => vec![crate::stake_tx::decode(payload)?.h.nullifier],
        // LIQUIDATION §10: the spent USDm note retires everywhere or the same note deposits once per node.
        Class::PoolDeposit => vec![crate::pool_tx::decode(payload)?.h.nullifier],
        // LIQUIDATION §10.2: the receipt retires everywhere or one receipt withdraws once per node.
        Class::PoolWithdraw => vec![crate::pool_tx::decode_withdraw(payload)?.h.nullifier],
        // ⛔⛔⛔ DB-274 P4b B1 — A ONE-TIME ID RETIRES AS A NULLIFIER (`peg::one_time_id_nf`), derived from the SAME key the
        // ledger's replay set keeps. Without it a producer re-carries a public, historical mint and every node that jumped
        // past the 512-id ring mints again; with it the canonical fold refuses the second carrier on every node.
        Class::PegIn => {
            let h = crate::peg_in_tx::decode(payload)?.0;
            vec![crate::peg::one_time_id_nf(crate::peg::ONE_TIME_DEPOSIT, &h.deposit_id)]
        }
        Class::WrappedMint => {
            let h = crate::wrapped_mint_tx::decode(payload)?.0;
            let key = crate::peg::wrapped_deposit_key(h.asset_id, &h.deposit_id);
            vec![crate::peg::one_time_id_nf(crate::peg::ONE_TIME_DEPOSIT, &key)]
        }
        Class::Liquidation => {
            let h = crate::liquidation_tx::decode(payload)?.0;
            let key = crate::peg::liquidation_key(h.epoch_id, h.asset_id, &h.position_id);
            vec![crate::peg::one_time_id_nf(crate::peg::ONE_TIME_LIQUIDATION, &key)]
        }
        // §BR-3 17.5: one repayment per state it moves — its `repay_id` is its own nullifier.
        Class::TheftRepayment => {
            let h = crate::theft_repayment_tx::decode(payload)?.0;
            vec![crate::peg::one_time_id_nf(crate::peg::ONE_TIME_THEFT_REPAY, &h.repay_id)]
        }
        // SAFE AT SCALE: one cost per foreign transaction — its ledger and that transaction's id are its own nullifier.
        Class::ReserveCost => vec![crate::reserve_cost_tx::decode(payload)?.one_time_id()],
        // §BR-8: one booking per payout, one return per outpoint
        Class::DecoyBatch => vec![crate::peg::one_time_id_nf(crate::peg::ONE_TIME_DECOY_BATCH, &crate::decoy_tx::DecoyBatchTx::decode(payload)?.payout_txid)],
        Class::DecoyReturn => {
            let t = crate::decoy_tx::DecoyReturnTx::decode(payload)?;
            vec![crate::peg::one_time_id_nf(crate::peg::ONE_TIME_DECOY_RETURN, &crate::decoy_tx::decoy_key(&t.txid, t.vout))]
        }
        // ⛔⛔⛔ DB-388 (rogue-role census, AssetCreate × REPLAY, 2026-10-04): a creation retired NOTHING, so a producer
        // re-carrying a public, historical creation was `Added` on every peer and `register_dsol_asset` APPENDED a duplicate
        // descriptor leaf each time — the registry root moved and its leaf count grew per block a producer chose (MEASURED by
        // `a_creation_re_carried_by_a_rogue_producer_moves_no_peer_registry_and_grants_no_second_issuance`). The creation's
        // one-time id is its own DERIVED asset id (recomputed from the descriptor by every node, never the claimed one): it
        // rides the publisher's lane, the graft door demands it, and the spent set refuses the second carrier exactly as it
        // refuses a note's second spend. The issuance right it plants is unchanged.
        // §BR-14: AND THE FEE NOTE'S NULLIFIER — the burn must travel, as for every spend.
        // A-F34: a creation WITH its supply retires the asset's issue right instead of the creation id
        // (`AssetCreateTx::own_nullifiers`, the one list)
        Class::AssetCreate => crate::asset_tx::AssetCreateTx::decode(payload)?.own_nullifiers(),
        // §BR-12 L1: a deploy retires its one-time id (its cid) and its fee note's nullifier on the lane (§9.6 #4)
        Class::DsolDeploy => crate::dsol_deploy_tx::DsolDeployTx::decode(payload)?.own_nullifiers(),
        // audit F15: a paid directory entry retires its fee note's nullifier on the lane (§9.6 #4)
        Class::DirEntry => crate::dir_entry_tx::DirEntryTx::decode(payload)?.own_nullifiers(),
        // IonSwap pools: an order's legs' nullifiers; a settlement's one-time id (pool, batch number)
        Class::IonOrder => crate::ion_pool_tx::IonOrderTx::decode(payload)?.own_nullifiers(),
        Class::IonSettle => crate::ion_pool_tx::IonSettleTx::decode(payload)?.own_nullifiers(),
        // §BR-12 L2: a call retires its fee note's nullifier and every Nullifier effect it emitted
        Class::DsolCall => crate::dsol_call_tx::DsolCallTx::decode(payload)?.own_nullifiers(),
        // §BR-12 L3: a fee update retires its one-time id over (cid, new fee)
        Class::DsolFeeUpdate => crate::dsol_fee_update_tx::DsolFeeUpdateTx::decode(payload)?.own_nullifiers(),
        // THE ISSUANCE RIGHT MUST TRAVEL: `H(domain ‖ asset_id)`, derivable from the object. Without it a mint omits
        // the burn, nothing retires the right, and the creator re-issues without bound (§AV).
        Class::AssetMint => {
            vec![crate::asset_tx::issue_right_nf(&crate::asset_tx::AssetMintTx::decode(payload)?.asset_id)]
        }
        // §BR-15: an order retires its burned note; a claim (or refund) retires its order's ONE claim nullifier.
        Class::DefiOrder => vec![crate::spend_frontier::leaf_to_cm_bytes(crate::defi_batch::DefiOrderTx::decode(payload)?.nullifier)],
        Class::DefiClaim => crate::defi_batch::DefiClaimTx::decode(payload)?.own_nullifiers(),
        // §18.12: every order slot's note and every claim slot's claim nullifier (a cover's lives in its own domain)
        Class::DefiSlots => crate::defi_batch::DefiSlotsTx::decode(payload)?.nullifiers(),
        // SATOSHI: one reward per note commitment — the spent set refuses a copied reward.
        Class::SatoshiReward => {
            let r = crate::satoshi::SatoshiRewardTx::decode(payload)?;
            vec![crate::satoshi::reward_nf(&r.note_cm()?)]
        }
        // §BR-3 17.3: the burned input's nullifier — the burn must travel, as for every spend.
        Class::SatDelegation => vec![crate::sat_delegation_tx::SatDelegationTx::decode(payload)?.nullifier],
        // §BR-3 17.5 layer 1: the burned note's nullifier — one fill per note
        Class::PotFill => vec![crate::pot_fill_tx::PotFillTx::decode(payload)?.nullifier],
        // §BR-4 B4-3: both burns' nullifiers — a unit closes once, a debt burn pays once
        Class::UnitClose => {
            let t = crate::unit_close_tx::UnitCloseTx::decode(payload)?;
            vec![t.unit_nullifier, t.debt_nullifier]
        }
        // §BR-4 B4-2: the unit's deposit id AND its Bitcoin deposit's id retire as one-time ids (one deposit, one unit)
        Class::UnitOpen => {
            let t = crate::unit_open_tx::UnitOpenTx::decode(payload)?;
            let h = crate::peg_in_tx::decode(&t.peg_in)?.0;
            vec![
                crate::peg::one_time_id_nf(crate::peg::ONE_TIME_DEPOSIT, &h.deposit_id),
                crate::peg::one_time_id_nf(crate::peg::ONE_TIME_DEPOSIT, &t.base_deposit_id),
            ]
        }
        // §BR-10: one attestation per (builder, release) — the spent set refuses a copy.
        Class::ReleaseAttestation => {
            let t = crate::release_attestation_tx::ReleaseAttestationTx::decode(payload)?;
            vec![crate::release_attestation_tx::attestation_nf(&t.builder(), &t.release_hash)]
        }
        // §BR-10: one signal per validator per window — the spent set refuses a second.
        Class::DeploymentSignal => {
            let t = crate::deployment_signal_tx::DeploymentSignalTx::decode(payload)?;
            vec![crate::deployment_signal_tx::signal_nf(&t.vid, t.bits, t.window)]
        }
        // §BR-9a: one deal per custodian per epoch — the spent set refuses a second.
        Class::EpochKeyDeal => {
            let t = crate::epoch_deal_tx::EpochKeyDealTx::decode(payload)?;
            vec![crate::epoch_deal_tx::deal_nf(&t.vid, t.epoch)]
        }
        // §BR-13: the set-aside's one-time id — the spent set refuses a second.
        Class::SatSetAside => vec![crate::sat_set_aside::set_aside_nf()],
        // §BR-3 17.6: one claim per (validator, index) — the spent set refuses a copied claim.
        Class::BondYieldClaim => {
            let t = crate::bond_yield_claim_tx::BondYieldClaimTx::decode(payload)?;
            vec![crate::bond_yield_claim_tx::claim_nf(&t.vid, t.y_now)]
        }
        // §BR-10: one payout per bounty nonce — the spent set refuses a second.
        Class::BountyPayout => vec![crate::bounty_payout_tx::bounty_nf(&crate::bounty_payout_tx::BountyPayoutTx::decode(payload)?.nonce)],
        // §BR-11: one payout per note commitment — the spent set refuses a copied payout.
        Class::MinerPayout => {
            let p = crate::miner_payout_tx::MinerPayoutTx::decode(payload)?;
            vec![crate::miner_payout_tx::payout_nf(&p.note_cm()?)]
        }
        // SATOSHI §6: the bonded note's nullifier — the burn must travel, as for every spend.
        // SATOSHI §9: a re-bond retires BOTH inputs (the fresh note and the consumed locked note).
        // ⛔ §9.3 R3 (lane-harness; DB-385's rule): a bond the named key did not sign owns NOTHING. The locked note's nullifier
        // is public once V's honest re-bond sits in a pool; a stranger-signed copy naming it must not justify it into the spent
        // set, or V's later unbond returns a note whose key is already spent (the bond unspendable forever).
        Class::SatBond => {
            let t = crate::sat_bond_tx::SatBondTx::decode(payload)?;
            if !t.is_authorised(&crate::pqauth::MlDsaVerifier) {
                return None;
            }
            t.own_nullifiers()
        }
        // THE BURN MUST TRAVEL: a transfer whose nullifier is absent credits two output notes and retires NOTHING
        // (the 2026-09-03 defect, wearing an asset's clothes).
        Class::AssetSpend => crate::asset_tx::AssetSpendTx::decode(payload)?.tags(),
        // ⛔ DB-258b — A SEAT REQUEST RETIRES ITS ONE-SHOT RIGHT, or an old request re-seats a validator that left.
        // ⛔⛔⛔ DB-385 (rogue-role census, MembershipBond × BURN, 2026-10-04): the right is derivable from the HEADER and
        // the NAMED KEY alone, so a request for V's real header signed by a STRANGER owned V's right here — the apply
        // door refused the seat ("not signed by the key it names") while the fold, reading THIS, justified the right
        // into the spent set: V's own genuine request was then refused as already spent, and one producer could
        // front-run every seat request it saw (validator-admission censorship). A request the named key did not sign
        // owns NOTHING — `None`, fail-closed at every reader: the pool door never pools it, the graft door lets it
        // justify nothing, the fold admits no tag for it. The apply door's rule (`is_authorised`), at the one site
        // every reader shares.
        Class::MembershipBond => {
            let (h, pk, sig) = crate::membership_bond_tx::decode(payload)?;
            if !crate::membership_bond_tx::is_authorised(&h, &pk, &sig, &crate::pqauth::MlDsaVerifier) {
                return None;
            }
            vec![crate::membership_bond_tx::seat_right_nf(&crate::membership_bond_tx::validator_id(&pk), &h)]
        }
        // DB-258d — an unbond retires its own one-shot right (`unbond_tx::unbond_right_nf`).
        // DB-385, the same rule on the unbond lane: a request the named key did not sign owns nothing — else a producer
        // burns V's unbond right with a stranger-signed copy and V's collateral stays locked (rogue-role census,
        // Unbond × burn).
        Class::Unbond => {
            let (h, pk, sig, _owner_clue) = crate::unbond_tx::decode(payload)?;
            if !crate::unbond_tx::is_authorised(&h, &pk, &sig, &crate::pqauth::MlDsaVerifier) {
                return None;
            }
            vec![crate::unbond_tx::unbond_right_nf(&crate::unbond_tx::validator_id(&pk), &h)]
        }
        _ => Vec::new(),
    })
}

pub fn wrapper_binds_object(tx: &crate::mempool::PqTx) -> bool {
    let Some((class, _)) = unframe(&tx.blob) else {
        #[cfg(test)]
        crate::test_census::vacuity::record("chain_object::wrapper_binds_object", true);
        return true; // an ordinary send — its own carrier gate judges it
    };
    #[cfg(test)]
    crate::test_census::vacuity::record("chain_object::wrapper_binds_object", false);
    let Some(notes) = carried_note_payloads(&tx.blob) else {
        return false; // framed but undecodable: nothing can justify a carriage
    };
    // ⛔⛔⛔ DB-224 — A TRANSACTION CARRIES WHOLE NOTES; A CARRIAGE IS NOT A TRANSACTION.
    //
    // Every note an honest object creates is one sealed `PQ_NOTE_BYTES` payload. A framed object whose
    // note fields are anything else is either a block's CARRIAGE form (64-byte references, [`carriage_of`])
    // or malformed — and neither may enter a pool: `output_notes` are concatenated into the block at
    // assembly and split on the fixed note width, so one short "note" misaligns every note after it. The
    // carriage case is not hypothetical: OrderFill's graft-side apply is `execute_order_fill`, which
    // RE-PUBLISHES the fill it reconstructs from the object it was handed. Refused here, that reconstruct-
    // and-publish arm is inert for a carried object (it answers `NotPublished` and writes nothing), and the
    // fill still settles from the block's own burn lane and notes. An empty PegOut change is no note.
    if notes.iter().any(|n| !n.is_empty() && n.len() != crate::cover::PQ_NOTE_BYTES) {
        return false;
    }
    let want: Vec<u8> = notes.concat();
    if tx.output_notes != want {
        return false; // the wrapper's carried value is not the object's own — a mint costume
    }
    if !tx.bond_notes.is_empty() || !tx.stake_notes.is_empty() {
        return false; // no framed class justifies a bond/stake divert of its notes
    }
    // ⭐ WHICH CLASSES MAY BURN. A credit / mint / creation / offer publishing a burn spends what nobody
    // spent, so the default is refusal. A FILL burns (its wrapper carries the node-padded lane, which is
    // deliberately not byte-derivable from the object) and a TRANSFER burns — and a transfer's burn IS
    // derivable, so it gets the stronger rule below that the fill cannot have.
    // ⭐ Z1 (2026-09-22): A MINT BURNS TOO — its issuance right's nullifier (`asset_tx::issue_right_nf`,
    // derivable from the object) rides this lane, and the strict rule below demands exactly it. The
    // sparse nullifier set then refuses the second mint as it refuses any double spend, which is what
    // closes infinite mint (§AV) now that the deletion tree is gone.
    // ⛔⛔⛔ A PEG-OUT AND A YIELD CLAIM BURN TOO — AND UNTIL 2026-09-17 THIS LINE REFUSED BOTH AT THE
    // PUBLISHER'S OWN POOL DOOR. `Node::peg_out_confidential` frames a `Class::PegOut` with the burned
    // USDm nullifier in its lane; `execute_yield_claim` frames a `Class::YieldClaim` with the stake
    // nullifier in its lane. Neither class was in this allow-list, so every one of those objects came
    // back `InvalidProof` from `ingest_tx` — and nobody saw it, because each executor had ALREADY applied
    // the transition locally and only logged the refusal. §CS-b and §CL were "closed" on objects that
    // never entered a pool. Found the moment the peg-out executor became verify-only (§CZ) and the
    // e2e's redeem answered BAD_REQUEST. Both burns are DERIVABLE from their object, so they get the
    // strict rule below (the lane must carry the object's own nullifier), like a transfer.
    // DB-274 P4b B1: a peg-in, a wrapped mint and a liquidation retire their one-time id on this lane too.
    if !matches!(
        class,
        Class::OrderFill
            | Class::AssetSpend
            | Class::SatBond
            | Class::PegOut
            | Class::YieldClaim
            | Class::AssetMint
            | Class::MembershipBond
            | Class::Unbond
            | Class::PegIn
            | Class::WrappedMint
            | Class::Liquidation
            | Class::TheftRepayment
            | Class::ReserveCost
            | Class::DecoyBatch
            | Class::DecoyReturn
            // DB-388: a creation retires its one-time id (its derived asset id) on this lane — the strict rule below demands
            // exactly it, so a re-carried creation is refused by the spent set instead of growing every registry.
            | Class::AssetCreate
            // §BR-12 L1: a deploy retires its cid's one-time id and its fee nullifier on this lane
            | Class::DsolDeploy
            // audit F15: a paid directory entry retires its fee nullifier on this lane
            | Class::DirEntry
            // IonSwap pools: an order retires its legs' nullifiers, a settlement its batch's one-time id, on this lane
            | Class::IonOrder
            | Class::IonSettle
            // §BR-12 L2: a call retires its fee nullifier and its Nullifier effect tags on this lane
            | Class::DsolCall
            // §BR-12 L3: a fee update retires its one-time id on this lane
            | Class::DsolFeeUpdate
            // LIQUIDATION §10: a pool deposit SPENDS a USDm note, a withdrawal SPENDS a receipt — each nullifier is the
            // object's own lane tag.
            | Class::PoolDeposit
            | Class::PoolWithdraw
            // §BR-3 17.3: a delegation burns its input note (its own nullifier rides the lane)
            | Class::SatDelegation
            // §BR-3 17.5 layer 1: a pot fill burns its input (its nullifier rides the lane)
            | Class::PotFill
            // §BR-4 B4-2: a unit open retires its two one-time deposit ids on this lane
            | Class::UnitOpen
            // §BR-4 B4-3: a unit close retires both burns' nullifiers on this lane
            | Class::UnitClose
            // §BR-3 17.6: a yield claim retires its one-time id on this lane
            | Class::BondYieldClaim
            // §BR-10: a bounty retires its nonce's one-time id on this lane
            | Class::BountyPayout
            // §BR-13: the set-aside retires its one-time id on this lane
            | Class::SatSetAside
            // §BR-10: a deployment signal retires its one-time id on this lane
            | Class::DeploymentSignal
            // §BR-10: a release attestation retires its one-time id on this lane
            | Class::ReleaseAttestation
            // §BR-9a: an epoch-key deal retires its one-time id on this lane
            | Class::EpochKeyDeal
            // §BR-15: an order burns its note, a claim (or refund) retires its order's claim nullifier — each on this lane
            | Class::DefiOrder
            | Class::DefiClaim
            | Class::DefiSlots
    ) && !tx.nullifiers.is_empty()
    {
        return false;
    }
    // ⛔⛔⛔ THE OBJECT'S OWN NULLIFIERS MUST RIDE THE WRAPPER'S LANE (DB-278: one definition, read here AND at the
    // graft door against the block's lane). The lane is cover-padded to a constant, so a real tag among covers reveals
    // nothing; its ABSENCE is what this refuses. With it, the second mint (or the second spend of a transferred note)
    // names a nullifier the sparse set already holds and the nullifier gate fails it closed at admit and at the block.
    let Some(own) = object_own_nullifiers(&tx.blob) else {
        return false;
    };
    own.iter().all(|nf| tx.nullifiers.iter().any(|n| n.as_bytes() == nf))
}

/// The payload half of a framed blob, or an empty slice. Used where the class is already known.
fn payload_of(blob: &[u8]) -> &[u8] {
    match unframe(blob) {
        Some((_, p)) => p,
        None => &[],
    }
}

/// ⭐ THE ADMISSION RULE — the ONE function `Node::ingest_tx` asks.
///
/// A framed blob is judged by its own class's rule, and a class with no self-contained rule yet is refused
/// by name.
///
/// ⛔⛔⛔ AN UNFRAMED BLOB — AN ORDINARY SEND — IS REFUSED HERE, AND THAT IS THE POINT.
///
/// This arm used to read `pqspend_direct_verify_carrier(blob).is_some()`, and it was the single widest hole
/// in the project. That verify is `verify_spend_carrier_bytes`: ONE row-local AIR (`in - out - fee == 0`)
/// whose ENTIRE public input is the CONSTANT `SPEND_CARRIER_DOMAIN` — one field element, ZERO slots for the
/// nullifier, the output commitments, the anchor root or the chain id. **A proof under that statement names
/// no transaction, so ONE carrier admitted EVERY transaction**, and building it needs no secret at all —
/// three integers. Reached from the gossip door, that arm let any peer mint: a tx with EMPTY `nullifiers`
/// (so the spend gates never engage) and arbitrary `output_notes` was ADMITTED, and `wrapper_binds_object`
/// passes an unframed blob through by design.
///
/// A SEND'S STATEMENT IS NOT SELF-CONTAINED IN ITS BLOB. What makes a send sound is the weld between the
/// proof and the transaction's OWN fields plus this node's OWN state — the anchor `spend_frontier_root()`,
/// both recorded output commitments, the recorded nullifier(s) and the membership cross-bind. None of those
/// are arguments here, so NO blob-only rule can judge a send, and pretending one could is what produced a
/// gate that proved nothing. The sound rule is therefore asked one level up, on the whole `PqTx`, at
/// `Node::admit_tx_shared` — and `false` here is the honest answer for a function holding only the blob.
///
/// This refuses nothing an honest sender sends TODAY: the production wallet's carrier is
/// `build_spend_validity_carrier_cross_bound` (a spend-VALIDITY carrier), which never satisfied the deleted
/// arm anyway; the conservation-only producer `build_spend_carrier` has NO production caller. So the set
/// this change stops admitting is exactly the set of forgeries.
///
/// ⚠️ WHAT REMAINS OPEN, NAMED: mempool GOSSIP of a send is now refused outright rather than refused by
/// accident. It was already refused in practice (the honest blob failed the deleted arm), and sends settle
/// because peers receive them through the BLOCK, not the pool. Restoring pool gossip needs the tx-level rule
/// on the gossip path too, which needs `spend_or_decoy_proof` to ride `PqTx` — it is currently parsed from
/// the HTTP body and is on NO wire struct, so `cover_ok` is unverifiable by any peer by construction.
///
/// `genesis_mint_allowance` is the chain's open-mint bound ([`crate::params::ChainParams::
/// genesis_mint_allowance`] — a pure function of the genesis identity, so a stranger derives it from chain
/// parameters alone): it is what makes the mint classes checkable with no oracle and no trusted issuer,
/// IDENTICALLY on every network. 0 (mainnet and every unknown network) means no mint-class object can be
/// satisfied — fail-closed until the bonded-threshold arm lands.
pub fn admissible(
    blob: &[u8],
    order_fill_fee_bps: u64,
    genesis_mint_allowance: u64,
    credit_attested: bool,
) -> bool {
    let Some((class, payload)) = unframe(blob) else {
        // No blob-only rule can judge a SEND — see this function's doc. Fail-closed.
        return false;
    };
    match class {
        Class::OrderFill => {
            let Some(f) = crate::order_fill_tx::OrderFillTx::decode(payload) else {
                eprintln!("[admit] REFUSE OrderFill: the payload is not a fill.");
                return false;
            };
            let (t, maker, taker) = (f.terms(), f.maker(), f.taker());
            // The SAME composed verification the settling node ran, at the SAME consensus fee rate — so a
            // peer reaches the identical verdict from the object alone and never from our word for it.
            let ok = usdm_decider::whir_rec_block::verify_order_fill(
                &f.maker_bytes,
                &maker,
                &f.taker_bytes,
                &taker,
                &t,
                order_fill_fee_bps,
            );
            if !ok {
                eprintln!(
                    "[admit] REFUSE OrderFill: the composed proof does not verify at this chain's fee rate."
                ); // DIGITAL-CASH-PRIVACY-REVIEWED: a branch name only; no tag, amount, key or owner.
            }
            ok
        }
        Class::OrderPost => {
            // An offer carries the maker's half, and the book's own gates judge it at apply. Admitting the
            // bytes only requires that they ARE an offer; a forged half is refused by `post_order`.
            let ok = decode_exact::<crate::order_book::OrderWire>(payload).is_some();
            if !ok {
                eprintln!("[admit] REFUSE OrderPost: the payload is not an offer.");
            }
            ok
        }
        // ⭐⭐⭐ THE MINT CLASSES — item 8(b), the self-contained mint-authority rule. Any stranger checks
        // each object from (its own bytes) + (chain parameters every node derives identically):
        //   1. the credited amount is within the chain's genesis-derived open-mint allowance
        //      (`ChainParams::genesis_mint_allowance` — testnet: the open faucet as a chain rule; mainnet
        //      and every unknown network: 0, unsatisfiable, fail-closed until the bonded ≥2/3 threshold
        //      arm is wired — the peg's `threshold_ok` model, the mainnet mint authority);
        //   2. where the class carries its own WHIR validity carrier (`AssetMint`), that carrier must
        //      prove the credited note opens to EXACTLY that amount in EXACTLY that asset
        //      (`verify_asset_mint_validity_bytes` — no over-mint, no wrong-asset, no "the caller
        //      chooses what it receives"). `BridgeCredit` does not carry one yet (the store-bound guard
        //      stack refused the field this session); on the only network where the class is satisfiable
        //      the allowance itself is the authority and the credited value is test value, and the
        //      bonded-threshold arm that opens mainnet MUST land the carrier with it.
        // No oracle, no trusted issuer, no `node_network_is_testnet` branch: the CODE is byte-identical on
        // every network and only the genesis-derived parameter differs, exactly like `chain_id`.
        // Every refusal line below is a FIXED string literal with no format args (BY CONSTRUCTION no tag,
        // amount, key or owner can appear in it).
        Class::BridgeCredit => {
            let Some(c) = crate::bridge_credit_tx::BridgeCreditTx::decode(payload) else {
                eprintln!("[admit] REFUSE BridgeCredit: the payload is not a credit.");
                return false;
            };
            // ⭐⭐⭐ THE MINT AUTHORITY IS **ALLOWANCE OR BONDED QUORUM**, AND BOTH ARMS ARE DECIDED
            // HERE — because this door binds the GRAFT path, not just the pool.
            //
            // ⛔⛔⛔ I FIRST MADE THIS ARM STRUCTURAL (tally at apply only, the WrappedMint division of
            // labour) AND THREE EXISTING PINS CAUGHT IT IMMEDIATELY:
            //     a_rogue_mainnet_producer_cannot_mint_a_credit_through_the_block_body
            //     a_testnet_valid_credit_is_refused_at_a_mainnet_and_unknown_genesis_door
            //     a_credit_the_mint_door_refuses_cannot_retire_a_staged_credit_on_either_party
            // The first says it exactly: *"the mint-authority rule binds only the POOL door, and a
            // producer that skips its own door mints on every honest peer at graft."* `admissible` is
            // reached from the graft door too, so moving the decision to apply opened the hole those
            // pins exist to keep shut. Not every class can borrow WrappedMint's shape — WrappedMint's
            // tally runs at ITS apply because that apply is the only door it has.
            //
            // ⭐ SO THE QUORUM VERDICT COMES TO THIS DOOR INSTEAD. `credit_attested` is computed by the
            // caller that HOLDS the bonded set (`Node::validators()`), against
            // `peg::PegLedger::bridge_credit_msg` and the ONE tally `peg::threshold_ok`. Callers with no
            // quorum pass `false` and this stays exactly as strict as it was before the arm existed —
            // fail-closed by default, never by remembering.
            //
            // ⛔ AND THE ALLOWANCE ARM IS UNCHANGED. A value-bearing network derives 0, so there a
            // credit is authorised ONLY by the quorum; an open-mint network is untouched.
            if c.amount > genesis_mint_allowance && !credit_attested {
                eprintln!(
                    "[admit] ⛔ REFUSE BridgeCredit: the credited amount exceeds this chain's \
                     genesis-derived open-mint allowance and no >=2/3 bonded quorum attests it."
                );
                return false;
            }
            true
        }
        // ⭐ SATOSHI §6 — the bond's blob-only half: the seating key's signature and the welded, asset-tagged carrier. The
        // membership half needs this node's own record roots and is asked at the fold (`sat_bond_tx::sat_bond_refusal`).
        Class::SatBond => {
            let Some(t) = crate::sat_bond_tx::SatBondTx::decode(payload) else {
                eprintln!("[admit] REFUSE SatBond: the payload is not a SAT bond.");
                return false;
            };
            if !t.is_authorised(&crate::pqauth::MlDsaVerifier) {
                eprintln!("[admit] REFUSE SatBond: not signed by the key it seats.");
                return false;
            }
            if !t.weld_is_authorised() {
                eprintln!("[admit] REFUSE SatBond: the carrier does not lock exactly the stated weight in SAT.");
                return false;
            }
            true
        }
        // §BR-15: the stateless halves — an order's burn (its share proof needs the book's threshold: the fold's), a claim's
        // relation and mint; a settlement and an expiry are decided against the book at the fold.
        // ⭐ §18.12: a lone order or claim would show the batch's count — each rides only inside its batch's slots
        Class::DefiOrder => {
            eprintln!("[admit] REFUSE DefiOrder: an order rides only in its batch's slots.");
            false
        }
        Class::DefiSlots => {
            let Some(t) = crate::defi_batch::DefiSlotsTx::decode(payload) else {
                eprintln!("[admit] REFUSE DefiSlots: not exactly the batch's slots, each bounded.");
                return false;
            };
            if let Some(why) = t.claims.iter().find_map(crate::defi_batch::DefiClaimTx::self_valid) {
                eprintln!("[admit] ⛔ REFUSE DefiSlots: a claim {why}."); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
                return false;
            }
            // ⭐ A-F26: every slot of one batch must name ONE anchor (a partition tells real from cover)
            let mut batch_anchor: Option<crate::spend_frontier::Digest4> = None;
            let all_same = t.orders.iter().map(|o| &o.member_tuple[..]).chain(t.claims.iter().map(|c| &c.member_tuple[..]))
                .all(|tuple| crate::member_transition::read_tuple(tuple).is_some_and(|mt| {
                    *batch_anchor.get_or_insert(mt.anchor) == mt.anchor
                }));
            if !all_same {
                eprintln!("[admit] ⛔ REFUSE DefiSlots: a slot names a different anchor than the batch's others (A-F26).");
                return false;
            }
            true
        }
        Class::DefiSettle => {
            if crate::defi_batch::DefiSettleTx::decode(payload).is_none() {
                eprintln!("[admit] REFUSE DefiSettle: not one canonical, bounded settlement.");
                return false;
            }
            true
        }
        Class::DefiExpire => {
            if crate::defi_batch::DefiExpireTx::decode(payload).is_none() {
                eprintln!("[admit] REFUSE DefiExpire: not one canonical expiry.");
                return false;
            }
            true
        }
        Class::DefiHandover => {
            if crate::defi_handover::DefiHandoverTx::decode(payload).is_none() {
                eprintln!("[admit] REFUSE DefiHandover: not one canonical, bounded handover object.");
                return false;
            }
            true
        }
        // ⭐ Earn step 3: the EarnEpoch's shape here; its audits against the books at the fold
        Class::DefiEarnEpoch => {
            if crate::defi_batch::DefiEarnEpochTx::decode(payload).is_none() {
                eprintln!("[admit] REFUSE DefiEarnEpoch: not one canonical, bounded EarnEpoch object.");
                return false;
            }
            true
        }
        Class::DefiClaim => {
            eprintln!("[admit] REFUSE DefiClaim: a claim rides only in its batch's slots.");
            false
        }
        // ⭐ SATOSHI — the reward's SHAPE and PROOF: the schedule's amount for its key (decode) and a carrier opening its note
        // to exactly that amount of SAT. Whether the key is the carrying block's own is a fact of the block, judged at its
        // fold (`Node::apply_sat_reward_at_fold`), with the cap.
        Class::SatoshiReward => {
            let Some(r) = crate::satoshi::SatoshiRewardTx::decode(payload) else {
                eprintln!("[admit] REFUSE SatoshiReward: not the schedule's reward (shape, width or amount).");
                return false;
            };
            if !r.credit_is_authorised() {
                eprintln!("[admit] REFUSE SatoshiReward: the carrier does not open the note to the scheduled SAT amount.");
                return false;
            }
            true
        }
        // §BR-11: the payout's shape and its note's recomputed commitment; its amount against the open quarter's rate and
        // the pool is a state question, decided at the fold (`Node::apply_miner_payout_at_fold`).
        Class::MinerPayout => {
            let Some(p) = crate::miner_payout_tx::MinerPayoutTx::decode(payload) else {
                eprintln!("[admit] REFUSE MinerPayout: not a payout (shape, width or a zero amount).");
                return false;
            };
            if !p.credit_is_authorised() {
                eprintln!("[admit] REFUSE MinerPayout: the note does not open to the stated USDm amount under its opening.");
                return false;
            }
            true
        }
        // §BR-10: the builder set is compiled into the release; the signature needs no state.
        Class::ReleaseAttestation => {
            let Some(t) = crate::release_attestation_tx::ReleaseAttestationTx::decode(payload) else {
                eprintln!("[admit] REFUSE ReleaseAttestation: not one canonical attestation.");
                return false;
            };
            if !t.authorised() {
                eprintln!("[admit] ⛔ REFUSE ReleaseAttestation: not signed by a builder of this release's set.");
                return false;
            }
            true
        }
        // §BR-9a: the deal's key and signature need no state; the roster, the dealing epoch and "once" are the fold's.
        Class::EpochKeyDeal => {
            let Some(t) = crate::epoch_deal_tx::EpochKeyDealTx::decode(payload) else {
                eprintln!("[admit] REFUSE EpochKeyDeal: not one canonical deal.");
                return false;
            };
            if !t.authorised() {
                eprintln!("[admit] ⛔ REFUSE EpochKeyDeal: the key or its signature does not verify.");
                return false;
            }
            true
        }
        // §BR-10: the signal's key and signature need no state; the seat and the open window are the fold's.
        Class::DeploymentSignal => {
            let Some(t) = crate::deployment_signal_tx::DeploymentSignalTx::decode(payload) else {
                eprintln!("[admit] REFUSE DeploymentSignal: not one canonical signal.");
                return false;
            };
            if !t.authorised() {
                eprintln!("[admit] ⛔ REFUSE DeploymentSignal: the key or its signature does not verify.");
                return false;
            }
            true
        }
        // §BR-13: the canonical bytes and the bound need no state; the once-only flag is the fold's.
        Class::SatSetAside => {
            let Some(t) = crate::sat_set_aside::SatSetAsideTx::decode(payload) else {
                eprintln!("[admit] REFUSE SatSetAside: not one canonical, bounded set-aside.");
                return false;
            };
            if !t.is_the_canonical_set_aside() {
                eprintln!("[admit] ⛔ REFUSE SatSetAside: not this network's canonical set-aside, or its bound does not verify.");
                return false;
            }
            true
        }
        // §BR-3 17.6: the claim's key, signature and carrier need no state; the index, the amount owed and the pool are the
        // fold's (`Node::bond_yield_claim_refusal`).
        Class::BondYieldClaim => {
            let Some(t) = crate::bond_yield_claim_tx::BondYieldClaimTx::decode(payload) else {
                eprintln!("[admit] REFUSE BondYieldClaim: not one canonical, bounded claim.");
                return false;
            };
            if !t.authorised() {
                eprintln!("[admit] ⛔ REFUSE BondYieldClaim: the key, its signature or the note's carrier does not verify.");
                return false;
            }
            true
        }
        // §BR-10: the bounty's signatures and carrier need no state; the quorum weight, the cap and the buffer are the fold's
        // (`Node::bounty_payout_refusal`).
        Class::BountyPayout => {
            let Some(t) = crate::bounty_payout_tx::BountyPayoutTx::decode(payload) else {
                eprintln!("[admit] REFUSE BountyPayout: not one canonical, bounded bounty.");
                return false;
            };
            if !t.signatures_and_carrier_verify() {
                eprintln!("[admit] ⛔ REFUSE BountyPayout: a signature or the note's carrier does not verify.");
                return false;
            }
            true
        }
        // §BR-4 B4-2: structural plus the unit note's carrier (stateless); custody's tally, the solvency and mint carriers, the
        // §BR-4 B4-3: the owner's carriers and the custody half's presence; the members, the day, the legs and the tally are the
        // fold's (`Node::unit_close`).
        Class::UnitClose => {
            let Some(t) = crate::unit_close_tx::UnitCloseTx::decode(payload) else {
                eprintln!("[admit] REFUSE UnitClose: not one canonical, bounded unit close.");
                return false;
            };
            if t.retire_leg.is_empty() || t.release_leg.is_empty() || t.attestors.is_empty() || !t.carriers_verify() {
                eprintln!("[admit] ⛔ REFUSE UnitClose: no custody half, or a burn does not prove.");
                return false;
            }
            true
        }
        // deposit-id set and the day/epoch exact checks are the fold's (`unit_open_tx::apply_chain_unit_open`).
        Class::UnitOpen => {
            let Some(t) = crate::unit_open_tx::UnitOpenTx::decode(payload) else {
                eprintln!("[admit] REFUSE UnitOpen: not one canonical, bounded unit open whose deposit id binds its unit.");
                return false;
            };
            if !t.unit_carrier_verifies() {
                eprintln!("[admit] ⛔ REFUSE UnitOpen: the unit note does not open to its unit's size and tag.");
                return false;
            }
            true
        }
        // §BR-3 17.5 layer 1: the buyer's carriers and a non-empty custody half need no state; the membership, the tally, the
        // retire leg, the pot and the floor are the fold's (`Node::pot_fill`).
        Class::PotFill => {
            let Some(t) = crate::pot_fill_tx::PotFillTx::decode(payload) else {
                eprintln!("[admit] REFUSE PotFill: not one canonical, bounded pot fill.");
                return false;
            };
            if t.retire_leg.is_empty() || t.attestors.is_empty() || !t.carriers_verify() {
                eprintln!("[admit] ⛔ REFUSE PotFill: no custody half, or its burn or SAT note does not prove.");
                return false;
            }
            true
        }
        // §BR-3 17.3: the conversion's two carriers need no state (tags, amount, the burn bound to the minted note); the
        // input's membership, the seat rule and the maturity are the fold's (`Node::sat_delegation_refusal`).
        Class::SatDelegation => {
            let Some(t) = crate::sat_delegation_tx::SatDelegationTx::decode(payload) else {
                eprintln!("[admit] REFUSE SatDelegation: not one canonical, bounded delegation.");
                return false;
            };
            if !t.carriers_verify() {
                eprintln!("[admit] ⛔ REFUSE SatDelegation: its burn or mint carrier does not verify for its tags and amount.");
                return false;
            }
            true
        }
        Class::AssetMint => {
            let Some(m) = crate::asset_tx::AssetMintTx::decode(payload) else {
                eprintln!("[admit] REFUSE AssetMint: the payload is not a mint.");
                return false;
            };
            // ⭐ SATOSHI is issued ONLY by mining: no asset mint may name its id or carry its in-circuit tag.
            if m.asset_id == crate::satoshi::asset_id() || m.asset_tag() == crate::satoshi::asset_tag() {
                eprintln!("[admit] REFUSE AssetMint: SAT is issued only as the mining reward.");
                return false;
            }
            // ⛔⭐⭐⭐ DB-200 — THE SAME CATEGORY ERROR, ONE CLASS OVER: A THIRD-PARTY ASSET'S SUPPLY WAS
            // BOUNDED BY THE USDm FAUCET.
            //
            // `genesis_mint_allowance` is the USDm open-mint bound and is ZERO on every chain but the
            // exact testnet identity, so `m.amount > 0` refused every mainnet mint: an asset that could
            // not be created (above) also could not be minted, which is why AssetCreate/AssetMint/
            // AssetSpend all sat unbacked in the readiness register.
            //
            // ⛔ IT IS NOT A NO-INFLATION GATE FOR USDm AND CANNOT BE ONE. `credit_is_authorised` below
            // verifies the mint carrier against `self.asset_tag()` IN-CIRCUIT, so the note this object
            // mints is welded to ITS OWN asset and is structurally incapable of being a USDm note.
            // Reaching USDm's tag from a descriptor would be a 2^-256 preimage on `derived_id()`.
            //
            // ⭐ WHAT BOUNDS SUPPLY INSTEAD — all three already here or at apply, all kept: the mint is
            // signed by the key that CREATED the asset (`creator_authorised`, immediately below — §AX
            // put it at this door precisely because gossip is the door an attacker uses); the carrier
            // opens the note to the authorised amount in that asset; and the asset must be a member of
            // this chain's token registry, folded to the node's own root at apply. An asset's own
            // issuance schedule is its descriptor's business and is judged against chain state at apply,
            // not against a faucet parameter at a blob-only door.
            // ⛔⛔⛔ §AX — THE CREATOR GATE MUST BE AT *THIS* DOOR, NOT ONLY AT THE PUBLISHER.
            //
            // §AT gave an asset an owner and enforced it in `Node::publish_asset_mint` and in
            // `asset_tx::apply_chain_asset_object`. MEASURED afterwards: the publisher is the door a
            // HONEST user walks through, and the graft-side function has ZERO production callers — so the
            // only door an attacker actually uses, GOSSIP, asked nothing about who was minting. A thief's
            // mint into someone else's asset passed `credit_is_authorised` (which proves only that the
            // carrier opens the note to the claimed amount, §AT), was pooled, rode a block, and its note
            // was recorded on every node. §AT was closed at the two doors nobody attacks.
            if !m.creator_authorised(&crate::pqauth::MlDsaVerifier) {
                eprintln!(
                    "[admit] ⛔ REFUSE AssetMint: not signed by the key that created this asset."
                );
                return false;
            }
            // The mint's own carrier binds cm <-> amount <-> asset.
            let ok = m.credit_is_authorised();
            if !ok {
                eprintln!(
                    "[admit] ⛔ REFUSE AssetMint: the note does not open to the authorised amount in \
                     this asset."
                );
            }
            ok
        }
        Class::AssetSpend => {
            let Some(t) = crate::asset_tx::AssetSpendTx::decode(payload) else {
                eprintln!("[admit] REFUSE AssetSpend: the payload is not a transfer.");
                return false;
            };
            // ⭐ UNLIKE AN ORDINARY SEND, A TRANSFER'S VALIDITY STATEMENT *IS* SELF-CONTAINED. The
            // asset-spend carrier's public bind names this transaction — both output commitments, the
            // nullifier and the membership cross-bind — so a proof under it admits THIS transfer and no
            // other. (The send carrier's entire public input is one constant, which is why no blob-only
            // rule can judge a send; see this function's doc.)
            //
            // ⛔ AND IT IS STILL ONLY HALF THE GATE. The carrier proves CONSERVATION and ONE ASSET; it
            // proves NOTHING about whether the spent note was ever received, because its membership
            // copath is a free witness (MEASURED — see `AssetSpendTx`'s doc). The membership half needs
            // this node's OWN record roots, so it is asked at the graft door
            // (`asset_tx::apply_chain_asset_object`). Admitting here on conservation alone keeps a
            // forged-value transfer out of the pool; it never installs anything.
            let ok = t.value_is_conserved();
            if !ok {
                eprintln!(
                    "[admit] ⛔ REFUSE AssetSpend: the carrier does not conserve value in one asset for \
                     the outputs this transaction carries."
                ); // DIGITAL-CASH-PRIVACY-REVIEWED: a branch name only; no tag, amount, key or owner.
            }
            ok
        }
        Class::Unbond => {
            // ⭐ SELF-VERIFYING FROM THE OBJECT ALONE. Every node checks the ML-DSA signature against the
            // id it RECOMPUTES as `H(pubkey)` — a claimed id is how you release someone else's bond, so
            // the object's own claim is never taken. No committee, no trusted issuer, no genesis
            // parameter: whoever holds the key may release their own weight and nobody else's.
            let Some((h, pubkey, sig, _owner_clue)) = crate::unbond_tx::decode(payload) else {
                eprintln!("[admit] REFUSE Unbond: the payload is not an unbond.");
                return false;
            };
            // DB-258: over the object's whole statement — validator, bonding, owner (the clue digest `decode` opened,
            // DB-273 §19.3 L2) and nonce. Whether that bonding is live is chain state, judged by `authorised_for` at graft.
            if !crate::unbond_tx::is_authorised(&h, &pubkey, &sig, &crate::pqauth::MlDsaVerifier) {
                eprintln!(
                    "[admit] ⛔ REFUSE Unbond: the signature is not the key-holder's over this unbond's own \
                     statement (validator, bonding, owner)."
                );
                return false;
            }
            true
        }
        Class::MembershipBond => {
            // ⭐ SELF-VERIFYING FROM THE OBJECT ALONE, exactly like Unbond: the ML-DSA signature against
            // the id every node RECOMPUTES as `H(pubkey)`. The POOL door judges the signature only;
            // whether a seat is FREE right now (reserve == 0) is chain state, and the graft-side door
            // `membership_bond_tx::apply_chain_membership_bond` decides it identically everywhere.
            let Some((h, pubkey, sig)) = crate::membership_bond_tx::decode(payload) else {
                eprintln!("[admit] REFUSE MembershipBond: the payload is not a membership bond.");
                return false;
            };
            if !crate::membership_bond_tx::is_authorised(&h, &pubkey, &sig, &crate::pqauth::MlDsaVerifier) {
                eprintln!(
                    "[admit] ⛔ REFUSE MembershipBond: the signature is not the key-holder's over this \
                     validator's own membership message and seat header."
                );
                return false;
            }
            true
        }
        // §BR-9a: the proof's shape needs no state; whether it convicts is the bond step's (it reads the epoch-key ledger).
        Class::EpochKeyFraud => {
            if crate::epoch_fraud_tx::decode(payload).is_none() {
                eprintln!("[admit] REFUSE EpochKeyFraud: not one canonical, bounded fraud proof.");
                return false;
            }
            true
        }
        Class::Equivocation => {
            // ⭐ SELF-VERIFYING FROM THE OBJECT ALONE (DB-266): both ML-DSA signatures under the object's one pubkey,
            // over two DIFFERENT blocks at ONE height, the voter id RECOMPUTED as `H(pubkey)`. Whether that voter is
            // bonded right now is chain state; the graft-side door `equivocation_tx::apply_chain_equivocation`
            // decides it identically everywhere.
            if crate::equivocation_tx::proves_equivocation(payload, &crate::pqauth::MlDsaVerifier).is_none() {
                eprintln!(
                    "[admit] ⛔ REFUSE Equivocation: the evidence does not prove two conflicting votes by one key \
                     at one height."
                );
                return false;
            }
            true
        }
        Class::FinalityVote => {
            // ⭐ SELF-VERIFYING FROM THE OBJECT ALONE (G2): one canonical cert of exact ML-DSA-65 widths, its signature under
            // the object's one pubkey over `finality_vote_msg(block, height)`, the voter id RECOMPUTED as `H(pubkey)`. Whether
            // that voter holds finality weight and whether the block sits at that height are chain state; the fold-side
            // door `finality_vote_tx::apply_chain_finality_vote` decides both identically everywhere.
            let Some(cert) = crate::finality_vote_tx::decode(payload) else {
                eprintln!("[admit] ⛔ REFUSE FinalityVote: not one canonical finality vote of ML-DSA-65 widths.");
                return false;
            };
            if crate::finality_vote_tx::is_authorised(&cert, &crate::pqauth::MlDsaVerifier).is_none() {
                eprintln!("[admit] ⛔ REFUSE FinalityVote: the signature is not the key-holder's over this block and height.");
                return false;
            }
            true
        }
        Class::PoolDeposit => {
            // Structural only, the stake object's division of labour: the epoch, the membership, the three carriers
            // against this node's own pool words — all at the fold apply (`Node::apply_pool_deposit_at_fold`).
            crate::pool_tx::decode(payload).is_some()
        }
        Class::PoolWithdraw => crate::pool_tx::decode_withdraw(payload).is_some(),
        Class::ReserveTheft => {
            // ⛔ DB-274 P4b (§8.15): STRUCTURE ONLY here — one canonical encoding, constant caps, distinct attestor
            // keys, exact ML-DSA-65 widths (`theft_tx::decode`). Whether ≥2/3 of the bonded weight signs it is decided
            // ONCE, at the carrying block's fold, against that step's pre-state set; this door holds no set to ask.
            if crate::theft_tx::decode(payload).is_none() {
                eprintln!("[admit] ⛔ REFUSE ReserveTheft: not one canonical, bounded theft object.");
                return false;
            }
            true
        }
        Class::BondTransition => {
            // ⛔ DB-313 §3 — a PRODUCER'S block-level statement, carried in `Block::bond_set` and judged at graft
            // (`note_transition::verify_bond`). No pool, gossip or submit door admits one: a pooled copy would ride
            // another block's bond lane as a second statement over bonds that block never proved.
            eprintln!("[admit] ⛔ REFUSE BondTransition: a block-level statement is never admitted to a pool.");
            false
        }
        Class::AssetCreate => {
            // ⛔⭐⭐⭐ DB-200 — THE USDm FAUCET BOUND WAS GATING ASSET CREATION, AND ON MAINNET IT CLOSED
            // THE WHOLE CLASS.
            //
            // WHAT STOOD HERE refused every creation unless `genesis_mint_allowance != 0`, and that
            // allowance is non-zero for EXACTLY ONE identity: `genesis_mint_allowance` returns
            // `TESTNET_OPEN_MINT_ALLOWANCE` for the exact testnet genesis prefix and `0` for every other
            // chain (`params.rs`, pinned by
            // `the_open_mint_allowance_derives_zero_for_every_genesis_but_the_exact_testnet_identity`).
            // So on MAINNET no user could create an asset at all, and the comment said so while calling
            // it a wait for "the bonded/fee door".
            //
            // MEASURED by `an_asset_cannot_be_created_at_all_so_it_cannot_travel_to_a_second_node`
            // (DB-193): `[asset-create] ⛔ REFUSED: could not be admitted as a transaction
            // (InvalidProof), so NOTHING was written.`
            //
            // ⛔ IT IS A CATEGORY ERROR, NOT A CONSERVATIVE BOUND. `genesis_mint_allowance` is the USDm
            // OPEN-MINT bound — the testnet faucet expressed as a chain rule. A creation mints no value
            // in USDm or in anything else: the ONLY note it may carry is the issue right
            // `H(domain ‖ asset_id)`, which every node recomputes from the creation's own bytes, and the
            // binding two hundred lines up refuses a creation carrying any other note BYTE-EXACTLY.
            // Pricing a non-minting object against the faucet allowance protects no supply.
            //
            // ⭐ AND NOTHING IS WEAKENED, BECAUSE THE GATES THAT DECIDE SUPPLY ARE ELSEWHERE AND ALL
            // THREE STAY. Minting that asset requires, at `apply_chain_asset_object`: the CREATOR's
            // ML-DSA signature; a carrier that opens the note to the authorised amount IN THAT ASSET
            // (`verify_asset_mint_validity_bytes` welds the asset tag IN-CIRCUIT, so a mint note can
            // never be a USDm note); and MEMBERSHIP of the descriptor in this chain's token registry,
            // folded to the node's own root — "its creation was never published" is refused there. An
            // attacker who publishes a creation naming someone else as creator produces an asset only
            // that victim's key can ever mint.
            //
            // THE DIVISION OF LABOUR IS THIS FILE'S OWN, stated at `Class::Liquidation` and
            // `Class::MembershipBond` directly above: the POOL door judges the BLOB — structure and
            // self-authorisation — and chain state is judged identically everywhere at apply. Registry
            // uniqueness and supply policy are chain state. Spam is priced by the tx's own PoW stamp and
            // fee, which every object pays, not by a parameter that only one genesis sets.
            // ⭐ §BR-14: AND THE FEE BURN'S CARRIER, which needs no state (the price, this creation's burn commitment, the
            // change and F are all in the object); its membership is the fold's (`Node::creation_fee_refusal`).
            let Some(c) = crate::asset_tx::AssetCreateTx::decode(payload) else {
                eprintln!("[admit] REFUSE AssetCreate: the payload is not a creation.");
                return false;
            };
            if !c.fee_carrier_verifies() {
                eprintln!("[admit] ⛔ REFUSE AssetCreate: its creation-fee burn does not verify.");
                return false;
            }
            // ⛔ A-F34: a creation that carries its supply is also a mint, and the gossip door asks a mint's three questions of
            // it here (§AX: this is the door an attacker uses): not SAT, signed by the key the asset's id binds, and the
            // carrier opens the note to the amount in this asset.
            if !c.supply_authorised(&crate::pqauth::MlDsaVerifier) {
                eprintln!("[admit] ⛔ REFUSE AssetCreate: its supply is not signed by the asset's creator, or its note does not open to the amount in this asset.");
                return false;
            }
            true
        }
        Class::DsolDeploy => {
            // §BR-12 L1 — the blob-only half of the deploy door (§9.6 #2): the bounds (decode), the deployer's ML-DSA-65
            // signature over the body, and the fee burn's carrier (the price into THIS deploy's burn commitment, the change,
            // the welded network fee). The fee note's membership and the contract-state path are chain STATE, judged at the
            // fold identically everywhere (`Node::dsol_deploy_refusal`).
            let Some(d) = crate::dsol_deploy_tx::DsolDeployTx::decode(payload) else {
                eprintln!("[admit] REFUSE DsolDeploy: the payload is not a deploy within the protocol's bounds.");
                return false;
            };
            if !d.signature_verifies() {
                eprintln!("[admit] ⛔ REFUSE DsolDeploy: the deployer's signature does not verify.");
                return false;
            }
            if !d.fee_carrier_verifies() {
                eprintln!("[admit] ⛔ REFUSE DsolDeploy: its deploy-fee burn does not verify.");
                return false;
            }
            true
        }
        Class::DirEntry => {
            // audit F15 — the blob-only half of the paid directory door (§9.6 #2): the bounds (decode), the entry's own
            // ML-DSA-65 signature and its profile binding, and the fee burn's carrier (the entry's price into THIS entry's
            // burn commitment, the change, the welded network fee). The fee note's membership and the directory's own rule
            // (first come, owner continuity) are chain STATE, judged at the fold identically everywhere
            // (`Node::dir_entry_refusal`, `Node::apply_dir_entry_at_fold`). A refusal here is returned and writes nothing.
            crate::dir_entry_tx::DirEntryTx::decode(payload).is_some_and(|t| t.self_authorised())
        }
        Class::IonOrder => {
            // IonSwap pools — the blob-only half of the order door (§9.6 #2): the bounds and the one-kind rule (decode) and
            // every leg's welded public-amount spend into THIS order's burn commitment. The spent notes' membership and
            // the pending list's room are chain STATE, judged at the fold identically everywhere (`Node::ion_order_refusal`).
            crate::ion_pool_tx::IonOrderTx::decode(payload).is_some_and(|t| t.legs_verify() && t.creator_verifies(&crate::pqauth::MlDsaVerifier))
        }
        Class::IonSettle => {
            // IonSwap pools — a settlement has no proof of its own: every word it carries is RECOMPUTED at the fold from
            // the ledger's pending orders and the row its path proves (`IonSettleTx::verdict`). Here: its bounds alone.
            crate::ion_pool_tx::IonSettleTx::decode(payload).is_some()
        }
        Class::DsolCall => {
            // §BR-12 L2 — the blob-only half of the call door: bounds (decode), the caller's signature, the statement's context
            // from the carried bytes, L2's effect policy, the fee carrier against the CARRIED manifest, every proof against its
            // carried code and the chain's authorisation. The manifest's truth (the state leaf), the fee note's membership and
            // the epoch are chain STATE, judged at the fold identically everywhere (`Node::dsol_call_refusal`).
            let Some(t) = crate::dsol_call_tx::DsolCallTx::decode(payload) else {
                eprintln!("[admit] REFUSE DsolCall: the payload is not a call within the protocol's bounds.");
                return false;
            };
            if let Some(why) = t.self_authorised() {
                eprintln!("[admit] ⛔ REFUSE DsolCall: {why}."); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
                return false;
            }
            true
        }
        Class::DsolFeeUpdate => {
            // §BR-12 L3 — the blob-only half: bounds, the deployer's signature against the carried manifest's deployer id, and
            // the direction (strictly lower). The manifest's truth (the leaf) is the fold's.
            let Some(t) = crate::dsol_fee_update_tx::DsolFeeUpdateTx::decode(payload) else {
                eprintln!("[admit] REFUSE DsolFeeUpdate: the payload is not a fee update within the protocol's bounds.");
                return false;
            };
            if let Some(why) = t.self_authorised() {
                eprintln!("[admit] ⛔ REFUSE DsolFeeUpdate: {why}."); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
                return false;
            }
            true
        }
        Class::Liquidation => {
            // WHAT A BLOB-ONLY RULE CAN DECIDE HERE, and what it deliberately cannot. It can decide the
            // object IS a liquidation, that its carrier is within the constant WHIR bound, and that it
            // carries attestors at all — the structural gates. It CANNOT tally the >=2/3 bonded weight or
            // verify the carrier, because both need node state this function does not have (the validator
            // set's bonds, and the peg's persisted commitments). Those are judged at apply by
            // [`crate::peg::PegLedger::liquidate_confidential`], the same division of labour
            // `Class::OrderPost` uses ("the book's own gates judge it at apply"). Admitting the BYTES is
            // not admitting the re-mark: a forged attestation set moves nothing, because the door tallies
            // real bonded weight over a domain-separated message and re-verifies the carrier against its
            // own digests. This arm logs nothing at all — a refusal here needs no line, and a silent
            // structural refusal cannot leak an amount, a commitment, a key or an owner.
            //
            // ONE CHECK, because the bounds live at the decode: `liquidation_tx::decode` refuses an empty or
            // over-bound carrier and an empty or over-cap attestation list before it returns anything, so this
            // arm inherits every structural bound instead of restating them (a restatement is how a second
            // reader ends up with a different idea of what is in bounds).
            crate::liquidation_tx::decode(payload).is_some()
        }
        // §BR-3 17.5: structural only, the liquidation's division of labour — the tally and the legs are the door's.
        Class::TheftRepayment => crate::theft_repayment_tx::decode(payload).is_some(),
        // §BR-8: structural only — the custody tally and the bonded decoy recipients are the fold's
        Class::DecoyBatch => crate::decoy_tx::DecoyBatchTx::decode(payload).is_some(),
        Class::DecoyReturn => crate::decoy_tx::DecoyReturnTx::decode(payload).is_some(),
        Class::PriceMark => {
            // Structural only, the SAME division of labour every attested class uses: this function holds
            // no node state, so it cannot tally bonded weight or know the epoch this node's mark came
            // from. Both are judged at apply by [`crate::peg::PegLedger::mark_price_attested`] — the
            // >=2/3 tally over each attestor's OWN signed price, and the monotone-epoch replay check.
            // Admitting the BYTES is not admitting the price: a forged quote set moves no mark. The
            // bounds (non-empty, <= the bonded ceiling, no zero price, key/sig ceilings) live at the
            // decode, so this arm inherits them.
            crate::price_mark_tx::decode(payload).is_some()
        }
        // SAFE AT SCALE: structural only, the registration's division of labour — the two vaults' tallies and the sum
        // proofs against this node's own pairs are the door's (`PegLedger::check_vault_merge`, at the fold). The bounds
        // (two distinct vaults, eight proof slots inside the decider's bound, 1..=32 signatures) live at the decode.
        Class::VaultMerge => crate::vault_merge_tx::decode(payload).is_some(),
        // SAFE AT SCALE: structural only — the vault's tally and the proofs against this node's own pair are the door's
        // (`PegLedger::check_reserve_cost`, at the fold). The bounds (a bridge ledger, a fee above zero, a bound proof
        // exactly past the floor) live at the decode.
        Class::ReserveCost => crate::reserve_cost_tx::decode(payload).is_some(),
        // SAFE AT SCALE, stage three: structural only — the vault's tally over the statement this node derives from its
        // own key record, the member set against this node's own seats and the retire's address window are the door's
        // (`PegLedger::check_vault_key_take` / `check_vault_key_retire`, at the fold). The bounds live at the decode.
        Class::VaultKey => crate::vault_key_tx::decode(payload).is_some(),
        // SAFE AT SCALE, stage three: structural only, the merge's division of labour — each step's tally, its sums against
        // this node's own pairs and slot, and the take's bound are the doors' (`PegLedger::check_vault_carve` /
        // `check_vault_take` / `check_vault_cancel`, at the fold). The bounds live at the decode.
        Class::VaultRebalance => crate::vault_rebalance_tx::decode(payload).is_some(),
        Class::WrappedAssetRegister => {
            // Structural only, the SAME division of labour `Class::Liquidation` uses: this function holds
            // no node state, so it cannot tally bonded weight or know the ratio this node currently
            // stands on. Both are judged at apply by
            // [`crate::peg::PegLedger::register_wrapped_asset_attested`] — the >=2/3 tally over the
            // domain-separated message AND the commitment-chain check that the attested `prev_ratio_bps`
            // is what this node holds. Admitting the BYTES is not admitting the ratio: a forged
            // attestation set moves nothing. The bounds live at the decode, so this arm inherits them.
            crate::wrapped_asset_tx::decode(payload).is_some()
        }
        Class::WrappedMint => {
            // Structural only, the same division of labour every attested class uses: the >=2/3 tally,
            // the carrier verify against this node's own digests and the deposit-id replay set all live
            // in `peg::wrapped_mint_confidential` at apply. The bounds live at the decode.
            crate::wrapped_mint_tx::decode(payload).is_some()
        }
        Class::PegIn => {
            // Structural only, the SAME division of labour: the ≥2/3 tally over
            // `peg::peg_in_confidential_msg`, the solvency-carrier verify against this node's own
            // persisted commitments, the bond backstop and the `confidential_deposit_ids` replay set all
            // live in `peg::peg_in_confidential` at apply, where the node holds the bonded set. The
            // bounds (attested, carriers present, non-zero amount, note long enough) live at the decode.
            crate::peg_in_tx::decode(payload).is_some()
        }
        Class::PegOut => {
            // Structural only, the same division of labour: the ≥2/3 tally over
            // `peg::peg_out_confidential_msg`, the redeem-floor carrier verify against this node's own
            // commitments and the `spent_burns` replay set all live in `peg::peg_out_confidential` at
            // apply. The bounds live at the decode.
            crate::peg_out_tx::decode(payload).is_some()
        }
        Class::YieldClaim => {
            // Structural only, the same division of labour: the epoch, the rate, the membership, the stake carrier and
            // the supply step all live at the fold apply (`Node::apply_stake_at_fold`). The bounds live at the decode.
            crate::stake_tx::decode(payload).is_some()
        }
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn a_frame_names_exactly_one_class_and_survives_the_round_trip() {
        for c in [
            Class::OrderFill,
            Class::OrderPost,
            Class::BridgeCredit,
            Class::AssetCreate,
            Class::AssetMint,
        ] {
            let framed = frame(c, b"payload");
            let (got, payload) = unframe(&framed).expect("a frame we wrote reads back");
            assert_eq!(got, c, "a framed object must read back as the class it was written as");
            assert_eq!(payload, b"payload");
        }
    }

    #[test]
    fn an_unframed_blob_is_never_mistaken_for_a_consensus_object() {
        // This is the property the dispatcher rests on: an ordinary send keeps going to the send gate.
        assert!(unframe(b"").is_none());
        assert!(unframe(b"MUS").is_none());
        assert!(unframe(b"MUSD").is_none(), "magic alone is not a frame — a class byte is mandatory");
        assert!(unframe(b"NOPE\x01payload").is_none());
        assert!(unframe(b"MUSD\x7fpayload").is_none(), "an unknown class byte is refused, never guessed");
    }

    /// ⭐⭐⭐ DB-200 — AN ASSET CREATION IS PERMISSIONLESS: THE SAME BYTES ADMIT ON EVERY CHAIN.
    ///
    /// ⛔ THIS PIN REPLACES A D-34 PIN THAT ASSERTED THE OPPOSITE, AND THE REPLACEMENT IS THE POINT.
    /// `the_asset_create_allowance_is_the_chains_and_the_same_bytes_flip_on_it_alone` required a valid
    /// creation to be REFUSED at allowance 0. That rule is what DB-200 removed: `genesis_mint_allowance`
    /// is the USDm open-mint bound and derives 0 for every identity but the exact testnet prefix, so the
    /// rule it pinned meant *no user could create an asset on mainnet at all*. The old pin was faithful to
    /// a door that was wrong; deleting it would have left the door unpinned in both directions, so it is
    /// rewritten to pin the CURRENT rule with both directions still asserted over the same bytes.
    ///
    /// WHAT IT STILL KILLS. The D-34 mutants aimed at the arm's allowance comparison
    /// (`M7_trust_from_peer_data@380` sourcing the allowance from the payload, `guard_disable`/`body_true`
    /// ignoring it). That comparison is gone from this arm, so the equivalent mutants are: a door that
    /// re-introduces a parameter gate (killed by the allowance-0 arm below — the exact regression that
    /// closed the class on mainnet) and a door that admits everything (killed by the two adversarial arms,
    /// which are asserted at BOTH parameter values so neither can pass by accident of the parameter).
    ///
    /// The chain-parameter authority property — "the same bytes flip on the chain's parameter alone" — is
    /// unchanged and still pinned, on the class where the allowance IS the rule: `BridgeCredit`, in
    /// `a_mint_class_is_unsatisfiable_where_the_genesis_derives_no_allowance` directly below, which
    /// asserts both directions over one well-formed credit.
    /// MUST-STAY-GREEN: `a_published_asset_creation_travels_to_a_second_node_in_a_block` (asset_tx.rs).
    #[test]
    fn an_asset_creation_is_permissionless_and_the_same_bytes_admit_on_every_chain() {
        let mut a = crate::asset_tx::AssetCreateTx {
            kind: crate::asset_tx::AssetKind::Token,
            symbol: "PIN".to_string(),
            name: "DB-200 permissionless pin".to_string(),
            logo: [0u8; 32],
            bytecode: vec![1, 2, 3, 4],
            creator: [0u8; 32],
            asset_id: [0u8; 32],
            fee: crate::asset_tx::CreationFee::default(),
            art: Vec::new(),
            supply: None,
        };
        // The id is RECOMPUTED by every node, so a descriptor is only well-formed once it carries its
        // own derivation — otherwise `decode` refuses and this pin would prove nothing about the door.
        a.asset_id = a.derived_id();
        // §BR-14: a creation carries its fee burn (a real carrier; membership is the fold's, not this blob-only door's).
        a.fee = crate::asset_tx::fee_leg_carrier_only_for_test(&a, 9);
        let blob = frame(Class::AssetCreate, &a.encode());

        // 1. ADMITTED WHERE THE GENESIS GRANTS AN ALLOWANCE (unchanged from the D-34 pin).
        assert!(
            admissible(&blob, 10, crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false),
            "a well-formed AssetCreate must be admitted on an open-mint chain"
        );

        // 2. ⭐ AND ADMITTED WHERE IT GRANTS NOTHING — THE DB-200 ARM. A creation mints no value: its
        //    only note is the issue right `H(domain ‖ asset_id)`, and minting the asset still requires
        //    the creator's ML-DSA signature, a carrier that welds the asset tag in-circuit, and
        //    membership in this chain's registry. Gating creation on the USDm faucet bound closed the
        //    class on every chain but testnet.
        assert!(
            admissible(&blob, 10, 0, false),
            "⛔ the identical creation was REFUSED where the genesis derives no allowance — that is \
             DB-200 returning: asset creation is closed on mainnet, so AssetCreate/AssetMint/AssetSpend \
             are unreachable for every real user"
        );

        // 3. THE DOOR STILL DISCRIMINATES, AT BOTH PARAMETER VALUES. Without these a door that simply
        //    returned `true` would pass 1 and 2.
        for allowance in [0, crate::params::TESTNET_OPEN_MINT_ALLOWANCE] {
            assert!(
                !admissible(&frame(Class::AssetCreate, b"not a creation"), 10, allowance, false),
                "garbage framed as a creation must never be admitted (allowance {allowance})"
            );
            let mut forged = a.clone();
            forged.symbol = "OTHER".to_string(); // keeps PIN's id while describing a different asset
            assert!(
                !admissible(&frame(Class::AssetCreate, &forged.encode()), 10, allowance, false),
                "⛔ a descriptor carrying another asset's id was admitted (allowance {allowance}) — that \
                 is identity theft at the asset layer, and every mint into it is a mint into somebody \
                 else's supply"
            );
            // ⛔ §BR-14: a creation with no fee burn, or with a burn proven for ANOTHER creation (lifted), is not admitted.
            let mut unpaid = a.clone();
            unpaid.fee = crate::asset_tx::CreationFee::default();
            assert!(!admissible(&frame(Class::AssetCreate, &unpaid.encode()), 10, allowance, false), "an unpaid creation was admitted");
            let mut other = a.clone();
            other.name = "another creation at the same price".to_string();
            other.asset_id = other.derived_id();
            let mut lifted = a.clone();
            lifted.fee = crate::asset_tx::fee_leg_carrier_only_for_test(&other, 9);
            assert!(
                !admissible(&frame(Class::AssetCreate, &lifted.encode()), 10, allowance, false),
                "⛔ a fee burn proven for another creation paid for this one (allowance {allowance})"
            );
        }
    }

    #[test]
    fn a_mint_class_is_unsatisfiable_where_the_genesis_derives_no_allowance() {
        // allowance = 0 is exactly what `ChainParams::genesis_mint_allowance()` yields for a mainnet (or
        // unknown-network) genesis — asserted by the params sibling test below the impl.
        for c in [Class::BridgeCredit, Class::AssetCreate, Class::AssetMint] {
            assert!(
                !admissible(&frame(c, b"anything at all"), 10, 0, false),
                "{c:?}: garbage must never be admitted, at any allowance"
            );
        }
        // A WELL-FORMED credit is still refused at allowance 0 — the amount bound is the authority.
        let c = crate::bridge_credit_tx::BridgeCreditTx {
            deposit_id: [7u8; 32],
            asset_tag: [0, 0, 0],
            amount: 1,
            note: vec![9u8; crate::cover::PQ_NOTE_BYTES],
            owner_clue: Vec::new(),
            attestors: Vec::new(),
        };
        assert!(
            !admissible(&c.wire(), 10, 0, false),
            "a well-formed credit MUST be refused where the genesis derives no allowance — this is the \
             mainnet fail-closed arm, and it must be the same code path testnet runs"
        );
        // The SAME bytes are admissible where the genesis derives an allowance covering the amount —
        // proving the parameter, not the code, is what differs between networks.
        assert!(
            admissible(&c.wire(), 10, crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false),
            "the same credit must admit under the testnet allowance — one rule, two parameters"
        );
    }

    /// ⭐ ITEM-8(b) ADVERSARIAL TAMPER PIN — a FORGED credit is REJECTED. The forgery that matters is the
    /// amount: a credit claiming more than the chain's allowance. RED without the 8(b) allowance bound BY
    /// CONSTRUCTION (no arm existed; nothing checked the amount against anything); GREEN with it.
    #[test]
    fn a_forged_credit_beyond_the_allowance_is_rejected_at_the_door() {
        let mut c = crate::bridge_credit_tx::BridgeCreditTx {
            deposit_id: [7u8; 32],
            asset_tag: [0, 0, 0],
            amount: crate::params::TESTNET_OPEN_MINT_ALLOWANCE,
            note: vec![9u8; crate::cover::PQ_NOTE_BYTES],
            owner_clue: Vec::new(),
            attestors: Vec::new(),
        };
        assert!(
            admissible(&c.wire(), 10, crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false),
            "PRECONDITION: an in-allowance credit admits"
        );
        c.amount = crate::params::TESTNET_OPEN_MINT_ALLOWANCE + 1;
        assert!(
            !admissible(&c.wire(), 10, crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false),
            "FORGERY: one unit over the chain's allowance must be refused by every node"
        );
        // A tampered CLASS byte is not a credit at all — the frame decides, never a guessed decode.
        c.amount = 1;
        let mut wrong_class = c.wire();
        wrong_class[MAGIC.len()] = Class::OrderFill as u8;
        assert!(
            !admissible(&wrong_class, 10, crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false),
            "a credit re-labelled as a fill must be judged (and refused) under the FILL's rule"
        );
    }

    /// ⭐ RED-TEAM forged-allowance PIN (2026-09-06) — AMOUNT-SHAPED forgeries at the door. Pure
    /// refusal assertions: nothing here admits, so no transition is claimed. (The exact-boundary
    /// ADMIT is already pinned by `a_forged_credit_beyond_the_allowance_is_rejected_at_the_door`'s
    /// precondition; this pin covers the extremes that could wrap or widen the compare.)
    ///
    /// ROOT-LAYER: `admissible`'s `c.amount > genesis_mint_allowance` compare — the ONE line standing
    /// between a forged credit amount and a pool slot, pinned where the compare lives.
    /// MEASURED: 18446744073709551615 (u64::MAX) is REFUSED at allowance 1000000000000 and at the
    /// near-MAX allowance 18446744073709551614 — no overflow, no wrap. RED check: inverting the
    /// compare or deleting the arm flips these assertions.
    /// MUST-STAY-GREEN: a u64::MAX credit is refused under every allowance below it.
    #[test]
    fn a_forged_credit_amount_never_slips_the_allowance_compare_at_any_extreme() {
        let c = crate::bridge_credit_tx::BridgeCreditTx {
            deposit_id: [11u8; 32],
            asset_tag: [0, 0, 0],
            amount: u64::MAX,
            note: vec![9u8; crate::cover::PQ_NOTE_BYTES],
            owner_clue: Vec::new(),
            attestors: Vec::new(),
        };
        assert!(
            !admissible(&c.wire(), 10, crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false),
            "FORGERY: a u64::MAX credit must be refused — no overflow, no wrap, no widened compare"
        );
        assert!(
            !admissible(&c.wire(), 10, u64::MAX - 1, false),
            "FORGERY: u64::MAX must exceed even a near-MAX allowance — the compare must not wrap"
        );
    }

    /// ⭐ RED-TEAM forged-allowance PIN (2026-09-06) — WIRE MALLEABILITY: one credit under MANY
    /// distinct byte encodings is a mint-door forgery even when every copy's amount is within the
    /// allowance. Pure refusal assertion: nothing here admits.
    ///
    /// ROOT-LAYER: `BridgeCreditTx::decode` (postcard). `postcard::from_bytes` deserializes a prefix
    /// and IGNORES trailing bytes, so `encode(c) || junk` decodes to the SAME credit while
    /// `PqTx::content_id` (blake3 of the whole blob) names a DIFFERENT transaction. The pool
    /// de-duplicates by content id, so ONE deposit could occupy unbounded pool slots and be carried
    /// by one block several times — the same commitment recorded at several leaf positions is the
    /// measured inflation class this crate's staged-credit and assembly docs name.
    /// MEASURED: 7 trailing bytes appended after the postcard payload; the padded wire differs from
    /// the canonical wire and MUST be refused. The first run (2026-09-06) decides RED or GREEN — a
    /// RED here is a CONFIRMED malleability hole and this pin is the specification of the
    /// decode-strictness fix.
    /// MUST-STAY-GREEN: a credit wire carrying trailing bytes is refused at the door.
    #[test]
    fn a_credit_wire_with_trailing_bytes_is_not_a_second_credit() {
        let c = crate::bridge_credit_tx::BridgeCreditTx {
            deposit_id: [13u8; 32],
            asset_tag: [0, 0, 0],
            amount: 1,
            note: vec![9u8; crate::cover::PQ_NOTE_BYTES],
            owner_clue: Vec::new(),
            attestors: Vec::new(),
        };
        let mut padded_payload = c.encode();
        padded_payload.extend_from_slice(&[0xEE; 7]);
        let padded_wire = frame(Class::BridgeCredit, &padded_payload);
        assert_ne!(padded_wire, c.wire(), "the padded wire is genuinely different bytes");
        assert!(
            !admissible(&padded_wire, 10, crate::params::TESTNET_OPEN_MINT_ALLOWANCE, false),
            "FORGERY: the same credit under a second byte encoding must be refused — one object, ONE \
             encoding; distinct content ids for one deposit let it occupy unbounded pool slots and be \
             carried more than once"
        );
    }

    /// ⭐ THE ENVELOPE (2026-10-05, the lenient-decode CLASS closed at every shippable site). Every gossip byte enters
    /// through `WireMsg::from_wire`; until tonight it was `postcard::from_bytes`, so a PADDED envelope decoded to the same
    /// message under different bytes — one message, two encodings, at the transport layer, under every class decoder
    /// that had already been made strict. RED-FIRST: this fails on the lenient decoder and passes on `decode_exact`.
    /// MUST-STAY-GREEN with `no_shippable_decode_in_the_node_accepts_trailing_bytes` (surface_census), the census twin.
    #[test]
    fn a_wire_envelope_with_trailing_bytes_is_not_a_second_message() {
        let m = crate::protocol::WireMsg::Tx(vec![7u8; 16]);
        let canonical = postcard::to_allocvec(&m).expect("the envelope encodes");
        assert!(crate::protocol::WireMsg::from_wire(&canonical).is_some(), "the exact envelope decodes");
        let mut padded = canonical.clone();
        padded.extend_from_slice(&[0xEE; 7]);
        assert_ne!(padded, canonical, "the padded envelope is genuinely different bytes");
        assert!(
            crate::protocol::WireMsg::from_wire(&padded).is_none(),
            "FORGERY: the same message under a second byte encoding must be refused at the envelope — one object, ONE \
             encoding; a tolerated tail is a second encoding of every message the envelope carries"
        );
    }

    /// ⭐ RED-TEAM HOLE-CLOSURE PIN (2026-09-06) — WIRE MALLEABILITY, offer class: the FIFTH decoder.
    /// The credit pin above covers `BridgeCreditTx`; this one covers the `OrderWire` decode the
    /// OrderPost admission arm runs, so every class the dispatcher knows is pinned strict. The
    /// TWO-PARTY half of this mechanism is already proven by the ingest pin
    /// `bridge_credit_tx::tests::an_oversized_credit_frame_is_refused_on_node_a_and_node_b`, where an
    /// independent node_a and node_b each refuse a padded frame at `ingest_tx`; THIS pin holds the
    /// same rule at the ROOT layer that door calls, for the offer class.
    ///
    /// ROOT-LAYER: the OrderPost arm of `admissible` — its `OrderWire` decode. A prefix-tolerant
    /// decode admits `payload || junk` as the SAME offer under a DIFFERENT content id, so one resting
    /// offer could occupy unbounded pool slots. Fixed by the same shared strict decode
    /// (`decode_exact`) every class arm uses.
    /// MEASURED: 7 trailing bytes appended after the postcard payload; the padded frame differs from
    /// the canonical frame and MUST be refused at the door. First run 2026-09-06 decides RED or GREEN
    /// — a RED is the confirmed malleability hole and this pin specifies the fix.
    /// MUST-STAY-GREEN: an offer frame carrying trailing bytes is refused at the door.
    #[test]
    fn an_offer_wire_with_trailing_bytes_is_not_a_second_offer() {
        let w = crate::order_book::OrderWire {
            lot: 100_000_000,
            pay_b: 250_000,
            asset_a: [0, 0, 0],
            asset_b: [1, 0, 0],
            expires_at_height: 1_000_000,
            nullifier: usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            leaf_commit: usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
            payout_cm: usdm_decider::poseidon2_compress::lanes_of(&[9, 10, 11, 12]),
            maker_bytes: vec![0xAA; 96],
            payout_note: vec![9u8; crate::cover::PQ_NOTE_BYTES],
            membership_carrier: Vec::new(),
            membership_tip: Vec::new(),
            payout_clue: crate::order_book::test_payout_clue(),
        };
        let payload = postcard::to_allocvec(&w).expect("an offer encodes");
        assert!(
            admissible(&frame(Class::OrderPost, &payload), 10, 0, false),
            "PRECONDITION: the canonical offer bytes admit at the door (the book's own gates judge \
             the maker half at apply)"
        );
        let mut padded = payload.clone();
        padded.extend_from_slice(&[0xEE; 7]);
        assert_ne!(padded, payload, "the padded payload is genuinely different bytes");
        assert!(
            !admissible(&frame(Class::OrderPost, &padded), 10, 0, false),
            "FORGERY: the same offer under a second byte encoding must be refused — one object, ONE \
             encoding; distinct content ids for one offer let it occupy unbounded pool slots"
        );
    }

    #[test]
    fn a_fill_that_does_not_verify_is_refused_at_the_door() {
        assert!(
            !admissible(&frame(Class::OrderFill, b"not a fill"), 10, 0, false),
            "bytes that are not a fill must not be admitted as one"
        );
    }

    fn a_note(tag: &[u8]) -> Vec<u8> {
        let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        n[..32].copy_from_slice(blake3::hash(tag).as_bytes());
        n
    }

    // ────────────────────────────────────────────────────────────────────────────────────────────
    // ⛔⛔⛔ DOOR AUDIT 2026-09-07, FAMILY B, §9.6 QUESTION 6 (PARITY). THIS IS A FIX SPEC.
    //
    // THE TWO DOORS. `Node::ingest_tx` (node.rs:16001) runs, in order:
    //   1. `chain_object::wrapper_binds_object`   (node.rs:16009)
    //   2. `Node::nullifier_witnesses_gate`       (node.rs:16022)
    //   3. `stage_carried_account_targets` / `stage_carried_note_clues`
    //   4. `mempool.accept_verified(tx, |blob| chain_object::admissible(blob, fee_bps, allowance))`
    //                                            (node.rs:16044-16046)
    // `Node::ingest_tx_prechecked` (node.rs:16059) runs 1, 2, 3 — and then `mempool.accept(tx)`
    // (node.rs:16083). Check 4, THE CLASS RULE ITSELF, is absent. It is the check that runs
    // `verify_order_fill` on a fill, the genesis-derived open-mint allowance on a credit or a mint,
    // `credit_is_authorised()` on a mint, and the send carrier gate on an unframed blob.
    //
    // THE DOOR'S OWN DEFENCE, quoted from node.rs:16060-16062: "A framed blob cannot have passed the
    // caller's off-lock send-carrier precheck, so this arm should be unreachable here". That premise
    // is false at the ONE caller. `rpc_http.rs:1823-1829` computes
    //   `let admit = ... else { direct_ok || spend_ok || multi_ok || cover_ok };`
    // and only `direct_ok` (rpc_http.rs:1269) is a function of `tx.blob`. `cover_ok`
    // (rpc_http.rs:1786-1802) reads ONLY `spend_or_decoy_proof` and `multi_nfs`; `multi_ok` and
    // `spend_ok` read other carried fields. So a submitter that attaches any one satisfiable
    // non-blob carrier reaches `submit_tx_prechecked` (rpc_http.rs:1890) → `ingest_tx_prechecked`
    // carrying a FRAMED blob the class rule would refuse. "Should be unreachable" is not a gate,
    // which is what the door's own comment says — and then it omits the gate anyway.
    //
    // WHAT IT COSTS AND WHAT IT DOES NOT. The produce-side assembly door (node.rs:1881) and the
    // graft door (node.rs:18336) re-ask `admissible`, so a forged object admitted here does not
    // become recorded value on an honest node — that is the sibling refusal §9.6 question 3 asks
    // about, and it holds. What this door loses is question 5: a forged object with a valid cover
    // proof occupies pool slots and weight on every node it is submitted to, is gossiped onward by
    // `submit_tx_prechecked` (node_runtime.rs:917), and is re-selected into template after template
    // where assembly silently drops it — a pool-capacity denial that costs the attacker one cover
    // proof and no valid object at all. The refusal belongs at the door, where its sibling puts it.
    //
    // THE FIX SPEC (one shared site, per §9.5): `ingest_tx_prechecked` must call
    // `mempool.accept_verified(tx, |blob| chain_object::admissible(blob, fee_bps, allowance))`
    // exactly as `ingest_tx` does — the class rule is stateless, so it costs the same under the lock
    // as off it, and the "prechecked" saving is the SEND carrier's ~4 ms ZK verify, which
    // `admissible` routes to only for an UNFRAMED blob. A tighter variant that keeps the whole
    // saving: refuse any FRAMED blob outright on this door (`unframe(&tx.blob).is_none()`), since
    // its one caller pre-verifies only the send carrier. Either is a check at one shared site.
    // ────────────────────────────────────────────────────────────────────────────────────────────

}

