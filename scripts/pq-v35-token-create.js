#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// pq-v35-token-create.js — decisive test: does the PQ carrier path carry a v35
// envelope?  (Step 1 of the PQ-aware Ion Swap DEX e2e.)
//
// Builds a TOKEN_CREATE PQ carrier (pq_create_transfer) whose extra_hex is the
// HF-v35 request marker (tag 0x2A) from build-1261/lib/v35-marker.cjs, then
// DRY-RUNS it against the daemon (sendrawtransaction do_not_relay).
//
//   • dry-run ACCEPTED  → pq_create_transfer's build path converted the 0x2A
//     marker into the 0x28 envelope (the PQ rail supports v35). Then we RELAY
//     (real TOKEN_CREATE on testnet — user authorized seeding) so the backend
//     v35 chain-scanner can ingest + materialize it.
//   • dry-run REJECTED with a 0x2A / tx_extra reason → the PQ path does NOT
//     convert the marker (the daemon's PQ carrier build needs v35 support — a
//     daemon-side finding to surface, NOT a backend gap).
//
// Run on the VPS (daemon 28080 + funded wallet-rpc 28084 are loopback there).
// Requires v35-marker.cjs alongside this file.

const http = require('http');
const { assembleV35Marker, V35_ROUTING_PUB } = require('./v35-marker.cjs');

const DAEMON = { host: '127.0.0.1', port: 28080 };
const WALLET = { host: '127.0.0.1', port: 28084, path: '/json_rpc' };
const PQ_MIN_FEE_ATOMIC = 100;
const BOND_ATOMIC = 100 * 1e8;            // 100 USDm TOKEN_CREATE bond (rule 15/47)
const MAX_SCAN = 8;
const RELAY_IF_ACCEPTED = process.env.RELAY === '1';   // gate the real broadcast

// A unique-ish testnet symbol per run so repeated runs don't collide on the
// pool id. No Date.now() in this env is fine — Date works in a plain node CLI.
const SYMBOL = (process.env.SYMBOL || ('PQT' + String(Date.now()).slice(-4))).slice(0, 6);

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
const daemonPost = (p, b) => post(DAEMON, '/' + p, b);
const walletRpc = (m, p) => post(WALLET, WALLET.path, { jsonrpc: '2.0', id: 0, method: m, params: p || {} })
  .then((r) => { if (r.error) throw new Error(m + ': ' + JSON.stringify(r.error)); return r.result; });

(async () => {
  // 1. classic primary address = creatorStealth (LP_MINT later signs with its
  //    spend key, so TOKEN_CREATE uses the same identity for consistency).
  const addr = await walletRpc('get_address', { account_index: 0 });
  const creatorStealth = addr.address;
  console.log('creatorStealth =', creatorStealth.slice(0, 20) + '…');
  console.log('routing_pub   =', V35_ROUTING_PUB.slice(0, 16) + '…  symbol =', SYMBOL);

  // 2. v35 marker for TOKEN_CREATE (no creator sig — not a stealth-debit op).
  const payload = {
    name: 'PQ Test ' + SYMBOL, symbol: SYMBOL, decimals: 8,
    maxSupply: String(1000000 * 1e8), supplyRule: 'fixed',
    description: 'PQ-rail e2e test token', metadataPublic: false,
    creatorFeeBps: 0, logoHash: null, creatorStealth,
  };
  const markerHex = assembleV35Marker({
    code: 'TOKEN_CREATE', payloadJson: JSON.stringify(payload),
    creatorStealthHex: '', creatorSigHex: '',
  });
  console.log('v35 marker    =', markerHex.length / 2, 'bytes (tag 0x' + markerHex.slice(0, 2) + ')');

  // 3. PQ carrier inputs.
  const tree = await daemonPost('get_pq_output_tree', {});
  if (!tree || !tree.notes_hex) throw new Error('no PQ output tree');
  const epoch = await daemonPost('get_pq_epoch_address', {});
  if (!epoch || epoch.status !== 'OK') throw new Error('epoch unconfigured: ' + JSON.stringify(epoch).slice(0, 120));
  const pqAddr = await walletRpc('get_pq_address', {});
  const recipient = pqAddr.pq_address || pqAddr.address;

  // 4. build the carrier (scan notes for one covering bond+fee), with the v35
  //    marker as extra_hex; dry-run each candidate.
  const SPENT = new Set(['invalid_input', 'double_spend']);
  let carrier = null, lastReason = null;
  for (let idx = 0; idx < MAX_SCAN; idx++) {
    let built;
    try {
      built = await walletRpc('pq_create_transfer', {
        note_index: idx, cmt_notes_hex: tree.notes_hex,
        recipient_address: recipient, amount: BOND_ATOMIC, fee: PQ_MIN_FEE_ATOMIC,
        epoch_address: epoch.epoch_address, extra_hex: markerHex,
      });
    } catch (e) { lastReason = e.message.slice(0, 140); console.log(`  note[${idx}] build: ${lastReason}`); continue; }
    if (!built || !built.carrier_tx_hex) { console.log(`  note[${idx}] no carrier`); continue; }
    const dry = await daemonPost('sendrawtransaction', { tx_as_hex: built.carrier_tx_hex, do_not_relay: true });
    const st = (dry && dry.status) || 'unknown';
    const reason = String((dry && dry.reason) || '').toLowerCase();
    if (st === 'OK') { carrier = built; console.log(`\n✅ DRY-RUN ACCEPTED at note ${idx} — PQ carrier carries the v35 marker/envelope (value=${built.value}).`); break; }
    lastReason = st + (reason ? ':' + reason : '');
    console.log(`  note[${idx}] dry-run ${lastReason}`);
    if (!(dry && (dry.double_spend || SPENT.has(reason))) && !reason.includes('exceed') && !reason.includes('insuffic') && !reason.includes('note value')) {
      // A non-spent, non-overspend rejection (e.g. tx_extra / 0x2a) — decisive.
      console.log('\n❌ Hard rejection (not a spent/too-small note). If this cites tx_extra/0x2a, the PQ build path does NOT convert the v35 marker → daemon-side v35 support needed on pq_create_transfer.');
      break;
    }
  }
  if (!carrier) { console.log('\nRESULT: no accepted v35 PQ carrier. lastReason =', lastReason); process.exit(1); }

  if (!RELAY_IF_ACCEPTED) {
    console.log('\n(Dry-run only. Re-run with RELAY=1 to broadcast the real TOKEN_CREATE for backend-ingestion validation.)');
    process.exit(0);
  }
  const relay = await daemonPost('sendrawtransaction', { tx_as_hex: carrier.carrier_tx_hex, do_not_relay: false });
  if (relay && relay.status === 'OK') {
    console.log(`\n🚀 RELAYED TOKEN_CREATE PQ carrier. symbol=${SYMBOL} value=${carrier.value}. The backend v35 chain-scanner should ingest + materialize it within ~1-2 blocks.`);
    console.log('   Verify: GET /testnet/api/tokens/' + SYMBOL + ' → tokenId, and the v35-scan log line.');
    process.exit(0);
  }
  console.log('\n❌ RELAY REJECTED:', JSON.stringify(relay).slice(0, 200));
  process.exit(1);
})().catch((e) => { console.error('FATAL:', e.message); process.exit(2); });
