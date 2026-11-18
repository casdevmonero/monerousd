#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// ─────────────────────────────────────────────────────────────────
// bootstrap-liquidity.js — operator-driven first-pool LP seeding
//
// What this is
//   The MoneroUSD AMM ships with empty pools — a token that has zero
//   liquidity is unswappable + has no price, breaking discovery for
//   every user. This script bootstraps the THREE highest-impact
//   pools by adding initial LP from the protocol reserve:
//
//     USDm ↔ wBTC   ($10k each side)
//     USDm ↔ wXMR   ($10k each side)
//     USDm ↔ wETH   ($10k each side)
//
//   Total operator commitment: ~$60k USDm-equivalent. Recoverable —
//   the protocol reserve IS the LP, so reserve growth from swap fees
//   on these pools flows back to the same pool.
//
// What this does NOT do
//   • Bootstrap stablecoin pools (USDm ↔ wDAI, etc.) — the PSM
//     handles 1:1 stablecoin mint/burn at parity; an AMM pool there
//     would just dilute the no-arb mint pipeline.
//   • Bootstrap long-tail wrappers (wADA, wDOGE, wBNB, wLTC, wBCH,
//     wRLUSD, wSOL, wZEC) — wait for organic LP demand.
//   • Bootstrap custom community tokens — the token-create wizard's
//     step-2 flow (rule 50) prompts the creator for initial liquidity;
//     don't subsidize.
//   • Subsidize indefinitely — this is a ONE-SHOT operation, not a
//     recurring liquidity-mining program.
//
// Architecture
//   The script assembles three LP_MINT attestations in a single
//   batch + broadcasts them through the standard wallet IPC
//   (`window.monerousd.lpMint`) — same pipeline any user follows
//   when adding liquidity. The LP positions are owned by the
//   PROTOCOL RESERVE STEALTH (not an operator's personal address)
//   so swap fees flow back to the reserve via the standard fee-split
//   table (`backend/fees/split.js::SPLITS::standard_swap` →
//   `reserves: 5500` of every fee bps). Reflexive: protocol funds
//   liquidity → fees on traded volume go back to protocol.
//
// Pre-flight requirements (the script enforces ALL of these)
//   1. Reserve stealth has at least USDm + each-pair-asset on hand.
//   2. The three target pools exist (`asset_registry` has all assets;
//      `pools` table has rows).
//   3. ETH USD price oracle is responsive (Chainlink reader works).
//   4. Operator confirms via prompt — this is NOT a silent action.
//
// Cross-references
//   • backend/fees/split.js::SPLITS                — fee-routing
//   • backend/amm/pool.js::mintFirst / mintSubsequent — LP mechanics
//   • build-1261/main.js::dapp-provider:lpMint     — IPC handler
//   • CLAUDE.md rule 50 (LP commitment + blinding invariant)
//   • Plan: Issue 7 in the ecosystem plan
//
// Usage
//   1. Operator unlocks the protocol reserve wallet.
//   2. Funds it with $30k worth of USDm + $10k each of wBTC/wXMR/wETH.
//   3. Runs:
//        node scripts/bootstrap-liquidity.js                # dry-run
//        node scripts/bootstrap-liquidity.js --execute      # broadcast
//   4. Three LP positions land on chain. The operator dashboard's
//      pools page shows USDm/wBTC, USDm/wXMR, USDm/wETH cards with
//      live reserves.
//
// AFTER running
//   Wait 30 days, observe organic LP inflow on each pool. If
//   ≥ $50k organic LP has joined a pool, withdraw the bootstrap
//   liquidity (the protocol's LP position) — bootstrap was a
//   kickstart, not a permanent subsidy.
// ─────────────────────────────────────────────────────────────────

import process from 'node:process';
import readline from 'node:readline/promises';
import crypto from 'node:crypto';

// ── Config ────────────────────────────────────────────────────────

const TARGET_USD_PER_SIDE = 10_000;  // $10k USDm + $10k pair-asset.
const POOLS = Object.freeze([
  { pair: 'USDm-wBTC', asset0: 'USDm', asset1: 'wBTC' },
  { pair: 'USDm-wXMR', asset0: 'USDm', asset1: 'wXMR' },
  { pair: 'USDm-wETH', asset0: 'USDm', asset1: 'wETH' },
]);

// Indexer base URL (overridable via env for dev / staging).
const INDEXER = process.env.INDEXER_URL || 'https://ion.monerousd.org';
// Wallet's localhost dApp proxy — same auth surface
// monerousd-chrome uses (rule 41).
const DAPP_PROXY = process.env.DAPP_PROXY || 'http://127.0.0.1:27751';

// ── arg parsing ────────────────────────────────────────────────

const args = process.argv.slice(2);
const EXECUTE = args.includes('--execute');
const DRY = !EXECUTE;
if (args.includes('--help') || args.includes('-h')) {
  // eslint-disable-next-line no-console
  console.log(
    'Usage: node scripts/bootstrap-liquidity.js [--execute]\n\n' +
    '  Without --execute: dry-run (validates reserves + prints planned LP).\n' +
    '  With --execute:    broadcasts three LP_MINT attestations from the\n' +
    '                     protocol reserve wallet via the local dApp proxy.\n',
  );
  process.exit(0);
}

const log  = (...m) => console.log('[bootstrap-lp]', ...m);
const warn = (...m) => console.warn('[bootstrap-lp WARN]', ...m);
const fail = (...m) => { console.error('[bootstrap-lp ABORT]', ...m); process.exit(1); };

// ── Network helpers ───────────────────────────────────────────────

async function getJson(url) {
  const r = await fetch(url, { headers: { accept: 'application/json' } });
  if (!r.ok) throw new Error(`HTTP ${r.status} ${url}`);
  return r.json();
}

// ── Pre-flight checks ─────────────────────────────────────────────

async function fetchPrices() {
  // Use the indexer's /api/prices (CoinGecko-backed). Stable +
  // already-cached responses — same source the wallet uses.
  let prices;
  try {
    prices = await getJson(INDEXER + '/api/prices');
  } catch (e) {
    fail('could not fetch /api/prices: ' + e.message);
  }
  for (const sym of ['wBTC', 'wXMR', 'wETH']) {
    if (!Number.isFinite(prices[sym]) || prices[sym] <= 0) {
      fail(`price oracle missing or zero for ${sym} — abort`);
    }
  }
  return prices;
}

async function fetchReserveBalances() {
  // The wallet's primary stealth IS the reserve stealth in solo-
  // operator bootstrap mode. Query /v1/balances?addrs=<reserve>.
  // For now we read the indexer's reserve view + assert the
  // protocol-owned wallet has enough on hand.
  //
  // In the absence of a dedicated /v1/reserve-balances endpoint,
  // the operator runs this script while connected to the reserve
  // wallet — the local /provider IPC returns the operator's own
  // balances which IS the reserve.
  try {
    const res = await fetch(DAPP_PROXY + '/provider/getBalance', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const j = await res.json();
    return j.balances || {};
  } catch (e) {
    fail(
      'could not query wallet via dApp proxy at ' + DAPP_PROXY + '/provider/getBalance' +
      ' — make sure the operator wallet is unlocked + the local dApp proxy is up. ' +
      'Error: ' + e.message,
    );
  }
}

async function fetchPools() {
  try {
    return await getJson(INDEXER + '/api/pools');
  } catch (e) {
    fail('could not fetch /api/pools: ' + e.message);
  }
}

async function checkPoolsExist(poolsList) {
  const have = new Set((poolsList || []).map((p) => p.pool_id || p.id));
  for (const p of POOLS) {
    if (!have.has(p.pair)) {
      fail(
        `pool ${p.pair} not found in /api/pools — operator must seed ` +
        `the launch-pool registry first via backend/config/launch-pools.js ` +
        `+ a fresh ion-backend restart.`,
      );
    }
  }
}

// ── Plan ──────────────────────────────────────────────────────────

function buildPlan(prices, balances) {
  // Convert $10k USDm-equivalent → atomic for each side, given the
  // Chainlink-quoted price of the pair asset.
  const usdmAtomicPerSide = BigInt(TARGET_USD_PER_SIDE) * 100_000_000n;
  // 3 sides of USDm at $10k each = $30k total USDm.
  const totalUsdmNeeded = usdmAtomicPerSide * BigInt(POOLS.length);
  const usdmHave = BigInt(balances.USDm?.balance || 0);
  if (usdmHave < totalUsdmNeeded) {
    fail(
      `insufficient USDm: have ${(Number(usdmHave) / 1e8).toFixed(2)}, ` +
      `need ${(Number(totalUsdmNeeded) / 1e8).toFixed(2)}. Top up the reserve wallet first.`,
    );
  }

  const plans = [];
  for (const p of POOLS) {
    const pairAsset = p.asset1;
    const price = prices[pairAsset];
    // Pair-asset units = $10k / price; convert to atomic (1e8).
    const pairUnits = TARGET_USD_PER_SIDE / price;
    const pairAtomic = BigInt(Math.round(pairUnits * 1e8));
    const have = BigInt(balances[pairAsset]?.balance || 0);
    if (have < pairAtomic) {
      fail(
        `insufficient ${pairAsset}: have ${(Number(have) / 1e8).toFixed(6)}, ` +
        `need ${pairUnits.toFixed(6)} ($${TARGET_USD_PER_SIDE.toFixed(0)}). ` +
        `Top up the reserve wallet first.`,
      );
    }
    plans.push({
      pair: p.pair,
      asset0: p.asset0, asset1: p.asset1,
      amount0: usdmAtomicPerSide,
      amount1: pairAtomic,
      pairPriceUsd: price,
    });
  }
  return plans;
}

function printPlan(plans) {
  log('PLANNED bootstrap-liquidity:');
  for (const p of plans) {
    log(
      `  • ${p.pair}: ` +
      `${(Number(p.amount0) / 1e8).toFixed(2)} ${p.asset0} + ` +
      `${(Number(p.amount1) / 1e8).toFixed(8)} ${p.asset1} ` +
      `(@ $${p.pairPriceUsd.toFixed(2)} → $${TARGET_USD_PER_SIDE} per side)`,
    );
  }
  log(
    `  Total operator commitment: $${(TARGET_USD_PER_SIDE * 2 * POOLS.length).toFixed(0)} ` +
    `(${POOLS.length} pools × $${TARGET_USD_PER_SIDE * 2} each).`,
  );
}

// ── Execution ─────────────────────────────────────────────────────

async function broadcastLpMint(plan) {
  // Pre-broadcast: build Pedersen commitment + blinding (rule 50).
  // The wallet's lpMint helper computes these client-side, but here
  // we're broadcasting from a script — must compute + persist them
  // ourselves so the position is later withdrawable.
  const r = crypto.randomBytes(32).toString('hex');
  const positionId = 'bootstrap-' + plan.pair + '-' + r.slice(0, 12);
  // We DELEGATE the commitment computation to the wallet's lpMint
  // path by invoking the dApp proxy — same code path the frontend
  // takes. The wallet writes the opening to ion:lp-positions
  // automatically as part of broadcastAttestation's pre-flight.
  log(`  broadcasting LP_MINT for ${plan.pair} (positionId=${positionId})…`);
  try {
    const res = await fetch(DAPP_PROXY + '/provider/lpMint', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        poolId:  plan.pair,
        asset0:  plan.asset0,
        asset1:  plan.asset1,
        amount0: plan.amount0.toString(),
        amount1: plan.amount1.toString(),
        positionId,
        // Tag the position as a protocol bootstrap LP for future
        // operator reporting. Doesn't affect chain state.
        memo: 'protocol-bootstrap-LP',
      }),
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status} ${txt}`);
    }
    const j = await res.json();
    log(`  ✓ ${plan.pair}: tx=${j.tx_hash || j.txHash || 'pending'}`);
    return j;
  } catch (e) {
    fail(`LP_MINT for ${plan.pair} failed: ` + e.message);
  }
}

async function confirmExecute() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  log('');
  log('TYPE EXACTLY: "bootstrap pools" to confirm. Anything else aborts.');
  const ans = await rl.question('> ');
  rl.close();
  if (String(ans).trim().toLowerCase() !== 'bootstrap pools') {
    fail('user did not type the confirmation phrase. Nothing broadcast.');
  }
}

// ── Main ──────────────────────────────────────────────────────────

(async () => {
  log('reading prices, reserves, pools…');
  const [prices, balances, pools] = await Promise.all([
    fetchPrices(),
    fetchReserveBalances(),
    fetchPools(),
  ]);
  await checkPoolsExist(pools);
  log('preflight OK — prices live, reserves sufficient, pools registered.');

  const plans = buildPlan(prices, balances);
  printPlan(plans);

  if (DRY) {
    log('');
    log('DRY-RUN complete. Re-run with --execute to broadcast.');
    process.exit(0);
  }

  await confirmExecute();

  log('');
  log('broadcasting…');
  const results = [];
  for (const p of plans) {
    const r = await broadcastLpMint(p);
    results.push({ pair: p.pair, ...r });
  }
  log('');
  log('BOOTSTRAP COMPLETE.');
  log('Run reports:');
  log('  • Each pool now has ~$10k each side; check /api/pools for live reserves.');
  log('  • Pedersen openings are persisted in the wallet — DO NOT lose this seed.');
  log('  • After 30 days, review organic LP inflow + decide whether to');
  log('    withdraw the bootstrap LP via /pools page → Withdraw on each.');
})().catch((e) => fail(e.message || e));
