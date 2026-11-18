#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/**
 * deploy-bridge-validator-bond.js — operator-side Phase 2 launch.
 *
 * Broadcasts DC_DEPLOY for BridgeValidatorBond.dsol via the canonical
 * staging-API + wallet-rpc transfer path (rule 46 — off-chain staging
 * + subaddress correlation). The wallet must be running on this
 * machine with wallet-rpc on 127.0.0.1:27750 (the auth-less,
 * localhost-only Electron spawn).
 *
 * Why this path (and not the dApp HTTP socket on :27751):
 *   - :27751 is the chrome-extension auth proxy. Bearer-token gated
 *     to the paired extension only. NOT a general operator surface.
 *   - The canonical operator-side pattern (mirrored from
 *     scripts/migration-real/*) is: stage off-chain → wallet-rpc
 *     transfer → backend chain-monitor dispatches.
 *   - The wallet approval modal is BYPASSED here because the
 *     operator's authorization IS running this script. The carrier-
 *     tx amount + recipient subaddress are still verifiable on
 *     chain after the fact.
 *
 * What this unlocks (CLAUDE.md rule 110e Phase 2):
 *   - Permissionless validator admission. Any wallet user can call
 *     window.monerousd.bondApply(...) → BOND_APPLY attestation lands
 *     on chain → ca-frost-validator-auto-grow daemon (--auto mode)
 *     polls applications + drives the DKG2-add ceremony.
 *   - Sybil-resistant bond curve (rule G-C). Contract enforces
 *     bondAmount * 10000 >= minBondAmount * (10000 + N²) on apply().
 *
 * Constructor args (frozen at deploy):
 *   _minBondAmount         = 1_000_000_000_000n (10000 USDm × 1e8;
 *                            rule G-C floor)
 *   _unbondingWindowBlocks = 10080 (14 days × 720 blocks/day at
 *                            120s block time — matches the comment
 *                            in bond-slash.js + validator-schema.js)
 *
 * Usage:
 *   node scripts/deploy-bridge-validator-bond.js [--dry-run]
 */
'use strict';

const fs   = require('node:fs');
const path = require('node:path');

const INDEXER_URL    = process.env.INDEXER_URL    || 'https://ion.monerousd.org';
const WALLET_RPC_URL = process.env.WALLET_RPC_URL || 'http://127.0.0.1:27750/json_rpc';
const DRY_RUN        = process.argv.includes('--dry-run');

// 10,000 USDm × 1e8 atomic = 1,000,000,000,000
const MIN_BOND_ATOMIC          = '1000000000000';
const UNBONDING_WINDOW_BLOCKS  = 10080;        // 14 days at 120s blocks
const DC_DEPLOY_BOND_ATOMIC    = 1_000_000_000;  // 10 USDm × 1e8 (DC-10)

const CONTRACT_DIR  = path.resolve(__dirname, '..', 'build-1261/dark-contracts/contracts/bridge-validator-bond');
const BYTECODE_PATH = path.join(CONTRACT_DIR, 'BridgeValidatorBond.dc');
const ABI_PATH      = path.join(CONTRACT_DIR, 'BridgeValidatorBond.abi.json');

async function rpc(method, params) {
  const r = await fetch(WALLET_RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: '1', method, params: params || {} }),
  });
  const j = await r.json();
  if (j.error) throw new Error(`wallet-rpc ${method}: ${j.error.message || JSON.stringify(j.error)}`);
  return j.result;
}

async function main() {
  // ── 1. Load + sanity-check the compiled artefacts ──────────────
  if (!fs.existsSync(BYTECODE_PATH)) fail(`Missing ${BYTECODE_PATH}.\n  Run: cd build-1261/dark-contracts && node cli/dsolc compile contracts/bridge-validator-bond/BridgeValidatorBond.dsol`);
  if (!fs.existsSync(ABI_PATH))      fail(`Missing ${ABI_PATH}.`);
  const bytecode    = fs.readFileSync(BYTECODE_PATH);
  const bytecodeB64 = bytecode.toString('base64');
  const abiJson     = fs.readFileSync(ABI_PATH, 'utf8');
  const abi         = JSON.parse(abiJson);
  if (abi.name !== 'BridgeValidatorBond') fail(`ABI name mismatch: got ${abi.name}.`);
  const ctor    = (abi.entrypoints || []).find((e) => e.name === 'constructor');
  const expArgs = ['_minBondAmount', '_unbondingWindowBlocks'];
  const actArgs = (ctor && ctor.args || []).map((a) => a.name);
  if (JSON.stringify(actArgs) !== JSON.stringify(expArgs)) {
    fail(`Constructor sig drift. Expected ${JSON.stringify(expArgs)}, got ${JSON.stringify(actArgs)}.`);
  }

  log(`▸ Deploying BridgeValidatorBond`);
  log(`  bytecode:               ${bytecode.length} bytes (${bytecodeB64.length} b64)`);
  log(`  _minBondAmount:         ${MIN_BOND_ATOMIC} (10000 USDm × 1e8)`);
  log(`  _unbondingWindowBlocks: ${UNBONDING_WINDOW_BLOCKS} (14 days at 120s blocks)`);
  log(`  carrier tx:             ${DC_DEPLOY_BOND_ATOMIC} atomic USDm (10 USDm bond)`);
  log('');

  // ── 2. Resolve the operator's primary subaddress + USDm balance ──
  // Rule: multi-asset wallet-rpc returns per-asset balances in
  // `result.balances[]` (with `all_assets: true`). The top-level
  // `unlocked_balance` is the FIRST asset's balance, which on this
  // wallet is empty. Read USDm explicitly from the breakdown.
  const addrInfo = await rpc('get_address', { account_index: 0 });
  const bal      = await rpc('get_balance',  { account_index: 0, all_assets: true });
  const usdmRow  = (bal.balances || []).find((b) => b.asset_type === 'USDm') || {};
  const unlocked = BigInt(usdmRow.unlocked_balance || 0);
  log(`▸ Operator subaddress:   ${(addrInfo.address || '').slice(0, 24)}…`);
  log(`  USDm unlocked balance: ${Number(unlocked) / 1e8} USDm`);
  if (unlocked < BigInt(DC_DEPLOY_BOND_ATOMIC)) {
    fail(`Insufficient USDm balance: need ${DC_DEPLOY_BOND_ATOMIC / 1e8} USDm unlocked, have ${Number(unlocked) / 1e8}.`);
  }
  log('');

  if (DRY_RUN) {
    log('▸ --dry-run set; stopping before staging + broadcast.');
    log(`  Next steps (without --dry-run): stage at ${INDEXER_URL}/api/attestation/stage,`);
    log(`  then wallet-rpc transfer ${DC_DEPLOY_BOND_ATOMIC} → returned subaddress.`);
    return;
  }

  // ── 3. Stage the attestation (rule 46) ─────────────────────────
  log('▸ Staging DC_DEPLOY at indexer');
  const payload = {
    bytecodeB64,
    abiJson,
    sourceHash: null,
    saltHex: '',
    constructorArgs: {
      _minBondAmount:         MIN_BOND_ATOMIC,
      _unbondingWindowBlocks: UNBONDING_WINDOW_BLOCKS,
    },
    stepLimit:   1_000_000,
    memoryLimit: 262_144,
  };
  const stageRes = await fetch(`${INDEXER_URL}/api/attestation/stage`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      code:    'DC_DEPLOY',
      payload,
      origin:  'https://ion.monerousd.org',
    }),
  });
  if (!stageRes.ok) {
    const txt = await stageRes.text().catch(() => '');
    fail(`Stage failed: HTTP ${stageRes.status}\n${txt}`);
  }
  const staged = await stageRes.json();
  if (!staged.address || !staged.opId) {
    fail(`Stage response missing fields: ${JSON.stringify(staged)}`);
  }
  log(`  opId:             ${staged.opId}`);
  log(`  stagedAddress:    ${staged.address.slice(0, 24)}…`);
  log(`  subaddressIndex:  ${staged.subaddressIndex ?? '?'}`);
  log('');

  // ── 4. Broadcast the carrier tx via wallet-rpc ─────────────────
  log('▸ Broadcasting carrier tx (10 USDm) via wallet-rpc');
  const tx = await rpc('transfer', {
    destinations: [{ address: staged.address, amount: DC_DEPLOY_BOND_ATOMIC }],
    account_index: 0,
    // Rule 44: don't pin subaddr_indices — let wallet-rpc pull from
    // the full account balance.
    priority: 1,
    ring_size: 16,
    get_tx_key: true,
  });
  log(`  ✓ tx_hash: ${tx.tx_hash}`);
  log(`  ✓ fee:     ${tx.fee} atomic (${Number(tx.fee) / 1e8} USDm)`);
  log('');

  // Best-effort notify the indexer that the tx is live (rule 40 —
  // optimization, not source of truth).
  try {
    await fetch(`${INDEXER_URL}/api/attestation/notify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: tx.tx_hash, origin: 'https://ion.monerousd.org', code: 'DC_DEPLOY' }),
    });
  } catch (_) { /* chain monitor will catch up */ }

  // ── 5. Poll for materialization ────────────────────────────────
  log('▸ Waiting for indexer to materialise the contract');
  let materialised = null;
  for (let i = 0; i < 90; i++) {
    await sleep(2000);
    try {
      const r = await fetch(`${INDEXER_URL}/v1/contracts`);
      if (r.ok) {
        const list = (await r.json()).contracts || [];
        const hit  = list.find((c) =>
          c.abi && c.abi.name === 'BridgeValidatorBond'
        );
        if (hit) {
          materialised = hit;
          break;
        }
      }
    } catch (_) { /* keep polling */ }
    if (i % 5 === 0) process.stdout.write('.');
  }
  process.stdout.write('\n');

  if (!materialised) {
    log('  ⚠ Indexer has not picked up the new contract within 180s.');
    log(`     The carrier tx is on chain — check`);
    log(`     ${INDEXER_URL}/v1/contracts/by-tx/${tx.tx_hash}`);
    log('     and rerun verification shortly. The contract may still materialise.');
    process.exit(0);
  }

  log(`  ✓ Indexer reports BridgeValidatorBond live`);
  log(`     contractId:     ${materialised.contractId}`);
  log(`     codeHash:       ${materialised.codeHash}`);
  log(`     creatorStealth: ${(materialised.creatorStealth || '').slice(0, 16)}…`);
  log('');
  log('▸ Phase 2 launch — operator follow-up:');
  log('');
  log('  ssh root@$MONEROUSD_VPS_HOST \\');
  log(`    "echo 'ION_VALIDATOR_BOND_CONTRACT_ID=${materialised.contractId}' \\`);
  log('     >> /etc/ion/backend.env && \\');
  log('     systemctl restart ion-backend.service"');
  log('');
  log('After that, every applied validator goes through the on-chain Sybil-resistant');
  log('bond curve + the ca-frost-validator-auto-grow daemon (--auto, t/n auto-recompute).');
}

function log(msg)  { process.stdout.write(`${msg}\n`); }
function fail(msg) { process.stderr.write(`✗ ${msg}\n`); process.exit(1); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

main().catch((err) => fail(err.stack || err.message));
