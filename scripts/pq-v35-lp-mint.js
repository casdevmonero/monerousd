#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// pq-v35-lp-mint.js — seed a USDm-<token> pool over the PQ rail (step 2 of the
// PQ-aware Ion Swap DEX e2e, after pq-v35-token-create.js materializes a token).
//
// LP_MINT is a CREATOR_STEALTH_AUTHED op (rule 110b): the carrier payload must
// carry a wallet-rpc spend-key signature over the canonical attestation. We
// reuse build-1261/lib/creator-stealth-auth.cjs (canonicalAttestation +
// generateSigOpId) verbatim so the bytes match what the backend verifier
// recomputes, and v35-marker.cjs to ride the full stamped payload on-chain.
//
// Flow: build LP_MINT payload -> sign(spend) -> embed in v35 marker -> build a
// PQ carrier (pq_create_transfer) whose VALUE is amount0 (real USDm liquidity,
// rule 15/47) and whose extra_hex is the marker -> dry-run -> relay. The backend
// v35 chain-scanner ingests it, recoverOnChainOp decrypts, dispatch() runs the
// LP_MINT (auto-creates the pool + credits reserves).
//
// Env: SYMBOL (e.g. PQT195), TOKENID (ion1_… from /api/tokens/SYMBOL),
//      AMOUNT0_USDM (display units, default 5000), AMOUNT1_TOKEN (display units,
//      default 50000), RELAY=1 to broadcast. Run on the VPS.

const http = require('http');
const { assembleV35Marker } = require('./v35-marker.cjs');
const { canonicalAttestation, generateSigOpId } = require('./creator-stealth-auth.cjs');
const crypto = require('crypto');

const DAEMON = { host: '127.0.0.1', port: 28080 };
const WALLET = { host: '127.0.0.1', port: 28084, path: '/json_rpc' };
const ION = { host: '127.0.0.1', port: 7787 };          // testnet backend (for tokenId lookup)
const PQ_MIN_FEE_ATOMIC = 100;
const UNIT = 1e8;
const MAX_SCAN = 8;

const SYMBOL = process.env.SYMBOL || 'PQT195';
const AMOUNT0_ATOMIC = Math.round(Number(process.env.AMOUNT0_USDM || 5000) * UNIT);
const AMOUNT1_ATOMIC = Math.round(Number(process.env.AMOUNT1_TOKEN || 50000) * UNIT);
const RELAY = process.env.RELAY === '1';

function post(opts, path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body || {});
    const req = http.request(
      { host: opts.host, port: opts.port, path, method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } },
      (res) => { let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => {
        try { resolve(JSON.parse(b)); } catch (e) { reject(new Error(path + ' parse: ' + b.slice(0, 200))); }
      }); });
    req.on('error', reject);
    req.setTimeout(180000, () => req.destroy(new Error(path + ' timeout')));
    req.write(data); req.end();
  });
}
function get(opts, path) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: opts.host, port: opts.port, path, method: 'GET' },
      (res) => { let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => {
        try { resolve(JSON.parse(b)); } catch (e) { resolve({ _raw: b.slice(0, 200) }); }
      }); });
    req.on('error', reject); req.setTimeout(15000, () => req.destroy(new Error(path + ' timeout')));
    req.end();
  });
}
const daemonPost = (p, b) => post(DAEMON, '/' + p, b);
const walletRpc = (m, p) => post(WALLET, WALLET.path, { jsonrpc: '2.0', id: 0, method: m, params: p || {} })
  .then((r) => { if (r.error) throw new Error(m + ': ' + JSON.stringify(r.error)); return r.result; });

(async () => {
  // 1. resolve tokenId for asset1 (creator-only first-deposit; backend enforces
  //    creator_stealth match against the registry for a custom token).
  let tokenId = process.env.TOKENID;
  if (!tokenId) {
    const t = await get(ION, '/api/tokens/' + encodeURIComponent(SYMBOL));
    tokenId = t && (t.token_id || t.tokenId);
    if (!tokenId) throw new Error('token ' + SYMBOL + ' not materialized yet (no tokenId): ' + JSON.stringify(t).slice(0, 160));
  }
  const poolId = 'USDm-' + SYMBOL;
  const addr = await walletRpc('get_address', { account_index: 0 });
  const creatorStealth = addr.address;
  console.log(`LP_MINT pool=${poolId} asset1=${tokenId.slice(0, 18)}… amount0=${AMOUNT0_ATOMIC} amount1=${AMOUNT1_ATOMIC}`);

  // 2. LP_MINT payload + rule-110b creator-stealth signature (byte-identical
  //    canonicalization via the shared lib).
  const r = crypto.randomBytes(32).toString('hex');
  const payload = {
    poolId, amount0: String(AMOUNT0_ATOMIC), amount1: String(AMOUNT1_ATOMIC),
    asset0: 'USDm', asset1: tokenId,
    commitment: r.slice(0, 64), positionId: 'pos-' + r.slice(0, 12),
    creatorStealth,
  };
  const sigOpId = generateSigOpId();
  payload.creatorStealthSigOpId = sigOpId;
  const canonical = canonicalAttestation({ code: 'LP_MINT', sigOpId, payload });
  const signRes = await walletRpc('sign', { data: canonical, account_index: 0, address_index: 0, signature_type: 'spend' });
  if (!signRes || !signRes.signature) throw new Error('wallet-rpc sign returned no signature');
  payload.creatorStealthSig = signRes.signature;
  console.log('  signed LP_MINT sigOpId=' + sigOpId.slice(0, 8) + '… sig=' + signRes.signature.slice(0, 14) + '…');

  // 3. v35 marker (full stamped payload rides inside payloadJson; daemon builds
  //    the 0x28 envelope from it during the PQ carrier construct).
  const markerHex = assembleV35Marker({
    code: 'LP_MINT', payloadJson: JSON.stringify(payload),
    creatorStealthHex: '', creatorSigHex: '',
  });
  console.log('  v35 marker = ' + markerHex.length / 2 + ' bytes');

  // 4. PQ carrier carrying amount0 USDm to the swap-wallet PQ address, extra=marker.
  const tree = await daemonPost('get_pq_output_tree', {});
  const epoch = await daemonPost('get_pq_epoch_address', {});
  if (!tree.notes_hex || !epoch || epoch.status !== 'OK') throw new Error('PQ inputs unavailable');
  const pqAddr = await walletRpc('get_pq_address', {});
  const recipient = pqAddr.pq_address || pqAddr.address;
  const SPENT = new Set(['invalid_input', 'double_spend']);
  let carrier = null, last = null;
  for (let idx = 0; idx < MAX_SCAN; idx++) {
    let built;
    try {
      built = await walletRpc('pq_create_transfer', {
        note_index: idx, cmt_notes_hex: tree.notes_hex, recipient_address: recipient,
        amount: AMOUNT0_ATOMIC, fee: PQ_MIN_FEE_ATOMIC, epoch_address: epoch.epoch_address, extra_hex: markerHex,
      });
    } catch (e) { last = e.message.slice(0, 120); continue; }
    if (!built || !built.carrier_tx_hex) continue;
    const dry = await daemonPost('sendrawtransaction', { tx_as_hex: built.carrier_tx_hex, do_not_relay: true });
    const st = (dry && dry.status) || '?'; const rs = String((dry && dry.reason) || '').toLowerCase();
    if (st === 'OK') { carrier = built; console.log(`  ✅ dry-run accepted at note ${idx} (value=${built.value})`); break; }
    last = st + ':' + rs; console.log(`  note[${idx}] ${last}`);
    if (!(dry && (dry.double_spend || SPENT.has(rs))) && !rs.includes('exceed') && !rs.includes('insuffic') && !rs.includes('note value')) break;
  }
  if (!carrier) { console.log('❌ no accepted LP carrier. last=' + last); process.exit(1); }

  if (!RELAY) { console.log('\n(dry-run only; re-run with RELAY=1 to seed the pool.)'); process.exit(0); }
  const relay = await daemonPost('sendrawtransaction', { tx_as_hex: carrier.carrier_tx_hex, do_not_relay: false });
  if (relay && relay.status === 'OK') {
    console.log(`\n🚀 RELAYED LP_MINT. Pool ${poolId} reserves should fill once mined + ingested.`);
    console.log('   Verify: GET :7787/api/pools → ' + poolId + ' reserve0/reserve1 > 0; then swap.');
    process.exit(0);
  }
  console.log('❌ relay rejected: ' + JSON.stringify(relay).slice(0, 200)); process.exit(1);
})().catch((e) => { console.error('FATAL:', e.message); process.exit(2); });
