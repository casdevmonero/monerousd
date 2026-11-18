#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// pq-carrier-test.js — de-risk the PQ value rail for the Ion Swap DEX.
//
// Proves the funded testnet wallet can SPEND its PQ notes by building a real
// confidential PQ transfer carrier (pq_create_transfer) and DRY-RUNNING it
// against the daemon (sendrawtransaction do_not_relay:true). The daemon runs
// the full membership + nullifier + balance verification on the dry-run
// WITHOUT broadcasting or consuming the note, so this is a safe probe.
//
// Mirrors build-1261/main.js::pq-build (the desktop's PQ Send rail):
//   daemon  :28080  get_pq_output_tree / get_pq_epoch_address / sendrawtransaction
//   wallet  :28084  /json_rpc  get_pq_address / pq_create_transfer
//
// Exit 0 + "DRY-RUN ACCEPTED" => PQ spend works; the DEX PQ carrier is viable.
// Run on the VPS (wallet-rpc + daemon are loopback there).

const http = require('http');

const DAEMON = { host: '127.0.0.1', port: 28080 };
const WALLET = { host: '127.0.0.1', port: 28084, path: '/json_rpc' };
const PQ_MIN_FEE_ATOMIC = 100;          // #45 floor (1e8 unit)
const SEND_ATOMIC = 100000000;          // 1 USDm test value
const MAX_SCAN = 8;                      // candidate note indices to try

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
const walletRpc = (method, params) => post(WALLET, WALLET.path,
  { jsonrpc: '2.0', id: 0, method, params: params || {} }).then((r) => {
    if (r.error) throw new Error(method + ': ' + JSON.stringify(r.error));
    return r.result;
  });

(async () => {
  console.log('=== 1. daemon PQ output tree (membership anchor) ===');
  const tree = await daemonPost('get_pq_output_tree', {});
  if (!tree || !tree.notes_hex) throw new Error('no PQ output tree: ' + JSON.stringify(tree).slice(0, 200));
  console.log('   notes_hex len =', tree.notes_hex.length);

  console.log('=== 2. daemon per-epoch fee address ===');
  const epoch = await daemonPost('get_pq_epoch_address', {});
  if (!epoch || epoch.status !== 'OK' || !epoch.epoch_address)
    throw new Error('epoch unconfigured: ' + JSON.stringify(epoch).slice(0, 200));
  console.log('   epoch_address =', epoch.epoch_address.slice(0, 24) + '...');

  console.log('=== 3. wallet PQ receive address (recipient = self for the probe) ===');
  const pqAddr = await walletRpc('get_pq_address', {});
  const recipient = pqAddr && (pqAddr.pq_address || pqAddr.address);
  if (!recipient) throw new Error('no PQ address: ' + JSON.stringify(pqAddr).slice(0, 200));
  console.log('   pq_address =', recipient.slice(0, 24) + '...');

  console.log('=== 4. build + dry-run PQ carrier, scanning note indices ===');
  const SPENT = new Set(['invalid_input', 'double_spend']);
  for (let idx = 0; idx < MAX_SCAN; idx++) {
    let built;
    try {
      built = await walletRpc('pq_create_transfer', {
        note_index: idx,
        cmt_notes_hex: tree.notes_hex,
        recipient_address: recipient,
        amount: SEND_ATOMIC,
        fee: PQ_MIN_FEE_ATOMIC,
        epoch_address: epoch.epoch_address,
      });
    } catch (e) { console.log(`   note[${idx}] build err: ${e.message.slice(0, 120)}`); continue; }
    if (!built || !built.carrier_tx_hex) { console.log(`   note[${idx}] no carrier`); continue; }
    const dry = await daemonPost('sendrawtransaction', { tx_as_hex: built.carrier_tx_hex, do_not_relay: true });
    const st = (dry && dry.status) || 'unknown';
    const reason = String((dry && dry.reason) || '').toLowerCase();
    if (st === 'OK') {
      console.log(`\n✅ DRY-RUN ACCEPTED at note_index=${idx}  value=${built.value} fee=${built.fee_value} spendable=${built.spendable_count}`);
      console.log('   PQ spend works → the DEX PQ carrier is viable. (Not relayed.)');
      process.exit(0);
    }
    const spent = dry && (dry.double_spend || SPENT.has(reason));
    console.log(`   note[${idx}] dry-run ${st}${reason ? ' (' + reason + ')' : ''}${spent ? ' [spent→next]' : ''}`);
    if (!spent && !reason.includes('overspend') && !reason.includes('exceeds') && !reason.includes('insufficient')) {
      console.log('   hard rejection — stopping scan.'); break;
    }
  }
  console.log('\n❌ No spendable PQ note produced an accepted carrier.');
  process.exit(1);
})().catch((e) => { console.error('FATAL:', e.message); process.exit(2); });
