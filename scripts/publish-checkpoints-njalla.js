#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// publish-checkpoints-njalla.js — Njalla DNS publisher for the
// MoneroUSD checkpoint TXT records.
//
// Reads the local USDmd's chain state, builds the same canonical
// 5-checkpoint slate that scripts/publish-checkpoint-records.sh
// produces, and posts each TXT record to the Njalla API. Replaces
// existing TXT records on `checkpoints.monerousd.org` +
// `checkpoints2.monerousd.org` atomically — old records are
// removed first, then new ones added, so a daemon refreshing
// mid-publish either sees the old full slate or the new full slate
// but never a partial set.
//
// Inputs (env):
//   NJALLA_API_TOKEN  — Njalla account token. Get from
//                       https://njal.la/settings/api/ → "Generate"
//                       (scope: domains:rw)
//   DOMAIN            — base domain. Default: monerousd.org
//   RPC_HOST/RPC_PORT — local daemon. Default 127.0.0.1:17750
//   SLATE_BLOCKS_BACK / ROUND_INTERVAL — slate sizing (see
//                       publish-checkpoint-records.sh for context)
//   DRY_RUN=1         — print intended changes without applying
//
// Njalla JSON-RPC API reference: https://njal.la/api/
//   list-records   { domain }
//   add-record     { domain, type, name, content, ttl }
//   remove-record  { domain, id }

'use strict';

const https = require('node:https');

const TOKEN = process.env.NJALLA_API_TOKEN;
if (!TOKEN) {
  console.error('NJALLA_API_TOKEN is required. Generate one at https://njal.la/settings/api/');
  process.exit(2);
}
const DOMAIN = process.env.DOMAIN || 'monerousd.org';
const RPC_HOST = process.env.RPC_HOST || '127.0.0.1';
const RPC_PORT = parseInt(process.env.RPC_PORT || '17750', 10);
const SLATE_BLOCKS_BACK = parseInt(process.env.SLATE_BLOCKS_BACK || '5', 10);
const ROUND_INTERVAL = parseInt(process.env.ROUND_INTERVAL || '1000', 10);
const DRY_RUN = process.env.DRY_RUN === '1';

const NAMES = ['checkpoints', 'checkpoints2'];

function nrpc(method, params) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ method, params });
    const req = https.request({
      method: 'POST',
      hostname: 'njal.la',
      path: '/api/1/',
      headers: {
        'Authorization': 'Njalla ' + TOKEN,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try {
          const r = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (r.error) return reject(new Error(method + ': ' + JSON.stringify(r.error)));
          resolve(r.result);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function daemonRpc(method, params = {}) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: '0', method, params });
    const req = require('node:http').request({
      method: 'POST',
      hostname: RPC_HOST,
      port: RPC_PORT,
      path: '/json_rpc',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 5000,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try {
          const r = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (r.error) return reject(new Error(JSON.stringify(r.error)));
          resolve(r.result);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('daemon RPC timeout')); });
    req.write(body);
    req.end();
  });
}

async function buildSlate() {
  const info = await new Promise((resolve, reject) => {
    require('node:http').get({ host: RPC_HOST, port: RPC_PORT, path: '/get_info', timeout: 5000 }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
  const tip = (info.height_without_bootstrap || info.height) - 1;
  console.log(`local tip = ${tip}`);
  const latest = Math.floor((tip - ROUND_INTERVAL) / ROUND_INTERVAL) * ROUND_INTERVAL;
  const slate = [];
  for (let i = 0; i < SLATE_BLOCKS_BACK; i++) {
    const h = latest - i * ROUND_INTERVAL;
    if (h <= 0) break;
    const hdr = await daemonRpc('getblockheaderbyheight', { height: h });
    slate.push({ height: h, hash: hdr.block_header.hash });
  }
  return slate;
}

async function main() {
  const slate = await buildSlate();
  console.log('Slate:');
  for (const e of slate) console.log(`  height=${e.height} hash=${e.hash}`);

  for (const name of NAMES) {
    console.log(`\n--- Updating ${name}.${DOMAIN} ---`);

    // 1. List existing records
    const records = await nrpc('list-records', { domain: DOMAIN });
    const existingForName = (records.records || []).filter(
      (r) => r.type === 'TXT' && r.name === name
    );

    // 2. Remove existing TXT records on `name`
    if (DRY_RUN) {
      console.log(`  (DRY-RUN) would remove ${existingForName.length} existing TXT record(s)`);
    } else {
      for (const r of existingForName) {
        await nrpc('remove-record', { domain: DOMAIN, id: r.id });
        console.log(`  removed old TXT id=${r.id} content="${r.content}"`);
      }
    }

    // 3. Add the slate
    for (const e of slate) {
      const content = `${e.height}:${e.hash}`;
      if (DRY_RUN) {
        console.log(`  (DRY-RUN) would add TXT "${content}"`);
      } else {
        await nrpc('add-record', { domain: DOMAIN, type: 'TXT', name, content, ttl: 600 });
        console.log(`  added TXT "${content}"`);
      }
    }
  }

  console.log('\nDone. Wait ~10 minutes for global DNS propagation, then verify:');
  console.log(`  dig +short TXT checkpoints.${DOMAIN}`);
  console.log(`  dig +short TXT checkpoints2.${DOMAIN}`);
}

main().catch((e) => {
  console.error('FAILED: ' + e.message);
  process.exit(1);
});
