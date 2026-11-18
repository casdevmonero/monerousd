// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// One-shot smoke test for pow_signal coinbase ingest.
// Run on the VPS via:
//   node /opt/ion-monerousd-org/backend/scripts/test-pow-ingest.mjs <block-height>

process.env.ION_DB = '/var/lib/ion-swap/state.db';
process.env.ION_USDM_RPC = 'http://127.0.0.1:17750/json_rpc';

const targetBlock = Number(process.argv[2]) || 118196;

const { ingestPowSignalsForBlock } = await import(
  '/opt/ion-monerousd-org/backend/governance/pow-signal-ingest.js'
);

console.log(`Calling ingestPowSignalsForBlock(${targetBlock}) ...`);
await ingestPowSignalsForBlock(targetBlock);

const Database = (await import('better-sqlite3')).default;
const db = new Database('/var/lib/ion-swap/state.db', { readonly: true });
const rows = db.prepare(
  'SELECT block_height, key, vote_value, recorded_at FROM pow_signals ORDER BY block_height DESC LIMIT 10'
).all();
console.log(`\npow_signals rows after ingest: ${rows.length}`);
for (const r of rows) {
  console.log(`  block=${r.block_height}  key=${r.key}  vote=${r.vote_value}`);
}

const proposalRow = db.prepare(
  "SELECT key, namespace, status FROM mimir_proposals WHERE key = 'Idea/test-pow-ingest-1'"
).get();
console.log(`\nmimir_proposals row for test key:`, proposalRow || '(not found)');
db.close();
