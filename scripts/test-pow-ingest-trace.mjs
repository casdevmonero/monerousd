// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// Verbose trace of every step of pow_signal ingest for one block.
// Bypasses ingestPowSignalsForBlock and replays the same logic
// inline so we can log between each gate.

process.env.ION_DB = '/var/lib/ion-swap/state.db';
process.env.ION_USDM_RPC = 'http://127.0.0.1:17750/json_rpc';

const targetBlock = Number(process.argv[2]) || 118196;
console.log(`\n[TRACE] target block: ${targetBlock}`);

const { parsePowSignalBlob, powSignalKeyHash16 } = await import(
  '/opt/ion-monerousd-org/backend/governance/pow-signal-parser.js'
);
const { recordPowSignal, listActiveProposals } = await import(
  '/opt/ion-monerousd-org/backend/governance/mimir.js'
);
const { getDb } = await import('/opt/ion-monerousd-org/backend/_db.js');

const DAEMON_RPC = 'http://127.0.0.1:17750/json_rpc';

async function rpc(method, params) {
  const r = await fetch(DAEMON_RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params }),
  });
  return (await r.json()).result;
}

async function fetchExtraHex(block) {
  const blockResp = await rpc('get_block', { height: block });
  const minerTxHash = blockResp?.miner_tx_hash || blockResp?.block_header?.miner_tx_hash;
  console.log(`[TRACE] miner_tx_hash for block ${block}: ${minerTxHash}`);
  const txResp = await fetch(DAEMON_RPC.replace('/json_rpc', '') + '/get_transactions', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ txs_hashes: [minerTxHash], decode_as_json: true }),
  });
  const txData = await txResp.json();
  const body = txData?.txs_as_json?.[0] ?? txData?.txs?.[0]?.as_json;
  if (!body) throw new Error('NO_BODY');
  const minerTx = JSON.parse(body);
  if (!Array.isArray(minerTx.extra)) return '';
  return minerTx.extra.map((b) => Number(b).toString(16).padStart(2, '0')).join('');
}

const extraHex = await fetchExtraHex(targetBlock);
console.log(`[TRACE] coinbase tx_extra hex (${extraHex.length / 2} bytes):`);
console.log(`[TRACE]   ${extraHex}`);

const signals = parsePowSignalBlob(extraHex);
console.log(`[TRACE] parsePowSignalBlob found ${signals.length} signal(s):`);
for (const s of signals) {
  console.log(`[TRACE]   keyHash16Hex=${s.keyHash16Hex}  voteByte=${s.voteByte}`);
}

// Trigger schema-init via mimir.js
listActiveProposals({ limit: 1 });

const db = getDb();
const proposalRows = db.prepare(
  'SELECT key FROM mimir_proposals UNION SELECT key FROM mimir_votes'
).all();
console.log(`[TRACE] mimir_proposals + mimir_votes have ${proposalRows.length} keys:`);
const keymap = new Map();
for (const r of proposalRows) {
  const h = powSignalKeyHash16(r.key);
  keymap.set(h, r.key);
  console.log(`[TRACE]   key='${r.key}' → hash16=${h}`);
}

console.log(`[TRACE] Looking up signals against keymap...`);
for (const sig of signals) {
  const k = keymap.get(sig.keyHash16Hex);
  console.log(`[TRACE]   sig hash=${sig.keyHash16Hex}  →  ${k ? "MATCH key='" + k + "'" : 'NO MATCH'}`);
  if (k) {
    try {
      const r = recordPowSignal({
        blockHeight: targetBlock,
        key: k,
        voteValue: sig.voteByte,
        attributionHint: null,
      });
      console.log(`[TRACE]   recordPowSignal returned:`, r);
    } catch (e) {
      console.error(`[TRACE]   recordPowSignal threw:`, e.message);
    }
  }
}

const after = db.prepare('SELECT * FROM pow_signals').all();
console.log(`\n[TRACE] pow_signals rows after (${after.length}):`);
for (const r of after) {
  console.log('  ', r);
}
