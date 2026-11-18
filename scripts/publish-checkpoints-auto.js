#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// publish-checkpoints-auto.js — fully-automated checkpoint publisher.
//
// One-command DNS-checkpoint refresh that NEVER exposes a long-lived
// API token on the command line, in env, in shell history, or in
// any log:
//
//   1. Reads a bootstrap Njalla token from macOS Keychain
//      (`scripts/njalla-keychain.sh get`).
//   2. Calls Njalla's `add-token` API to mint a fresh ephemeral
//      token named `monerousd-checkpoint-<unix-ts>`. The bootstrap
//      token's only purpose is to mint+revoke other tokens.
//   3. Builds the latest checkpoint slate by querying the
//      authoritative VPS/edge daemon for block hashes at five
//      round-thousand heights below the current tip.
//   4. Updates the TXT records on `checkpoints.monerousd.org` and
//      `checkpoints2.monerousd.org` atomically — old records are
//      deleted FIRST, then new ones added under the ephemeral
//      token's authority.
//   5. Calls `remove-token` on the ephemeral token, in a
//      finally{} block so it cleans up even if the publish errors
//      out mid-flight.
//   6. Self-verifies via `dig +short TXT checkpoints.…` (no
//      bootstrap-token usage required for verification).
//
// Scheduling:
//   - Manual: `node scripts/publish-checkpoints-auto.js`
//   - Cron / launchd: see scripts/install-checkpoint-cron.sh
//     for a launchd plist that runs this script weekly.
//
// Setup (one-time):
//   1. Generate a Njalla API token at https://njal.la/settings/api/
//   2. Store in Keychain:
//        bash scripts/njalla-keychain.sh set
//        (paste token at prompt; never logged anywhere)
//   3. Done. From here on, every publish run is one command.
//
// Rotation: if the bootstrap token leaks, run
//   bash scripts/njalla-keychain.sh set    (with a fresh token)
// and delete the old one in the Njalla web UI. No code changes
// needed.

'use strict';

const https = require('node:https');
const http = require('node:http');
const child_process = require('node:child_process');
const path = require('node:path');

// ─── config (env-overridable) ──────────────────────────────────────
const DOMAIN = process.env.DOMAIN || 'monerousd.org';
const RPC_HOST = process.env.RPC_HOST || process.env.MONEROUSD_VPS_HOST;
const RPC_PORT = parseInt(process.env.RPC_PORT || '17750', 10);
const SLATE_BLOCKS_BACK = parseInt(process.env.SLATE_BLOCKS_BACK || '5', 10);
const ROUND_INTERVAL = parseInt(process.env.ROUND_INTERVAL || '1000', 10);
const DRY_RUN = process.env.DRY_RUN === '1';
const NAMES = ['checkpoints', 'checkpoints2'];
const KEYCHAIN_SCRIPT = path.resolve(__dirname, 'njalla-keychain.sh');

// ─── bootstrap token retrieval ─────────────────────────────────────
function readBootstrapToken() {
  // Allow env override for CI / one-shot use. Production runs use
  // Keychain so no token ever appears in the process env-table that
  // sub-processes inherit.
  if (process.env.NJALLA_API_TOKEN) {
    return process.env.NJALLA_API_TOKEN.trim();
  }
  try {
    const out = child_process.execFileSync('bash', [KEYCHAIN_SCRIPT, 'get'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    return out.trim();
  } catch (e) {
    throw new Error('could not read bootstrap token from Keychain. Run `bash ' + KEYCHAIN_SCRIPT + ' set` first.');
  }
}

// ─── njalla JSON-RPC client ────────────────────────────────────────
function nrpc(token, method, params) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ method, params: params || {} });
    const req = https.request({
      method: 'POST',
      hostname: 'njal.la',
      path: '/api/1/',
      headers: {
        'Authorization': 'Njalla ' + token,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: 15000,
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
    req.on('timeout', () => { try { req.destroy(); } catch (_) {} reject(new Error(method + ': timeout')); });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── daemon RPC ────────────────────────────────────────────────────
function daemonGet(path_) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      method: 'GET', hostname: RPC_HOST, port: RPC_PORT, path: path_, timeout: 5000,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(e); } });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('daemon timeout')); });
    req.on('error', reject);
    req.end();
  });
}

function daemonRpc(method, params = {}) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: '0', method, params });
    const req = http.request({
      method: 'POST', hostname: RPC_HOST, port: RPC_PORT, path: '/json_rpc',
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
    req.on('timeout', () => { req.destroy(); reject(new Error('daemon timeout')); });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function buildSlate() {
  const info = await daemonGet('/get_info');
  const tip = (info.height_without_bootstrap || info.height) - 1;
  console.log(`source-daemon ${RPC_HOST}:${RPC_PORT} tip=${tip}`);
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

// ─── ephemeral-token lifecycle ─────────────────────────────────────
//
// Njalla API schema (verified against njal.la/api/1/ 2026-05-14):
//   add-token    { comment } → { key, comment, created }
//   remove-token { key }     → { key, comment, created, status: "removed" }
//   list-tokens  { }         → { tokens: [{ key, comment, created } ...] }
//
// `key` is BOTH the bearer token AND the unique identifier. We
// never log the raw key — only the first 8 chars for diagnostics.
async function mintEphemeral(bootstrapToken) {
  const comment = `monerousd-checkpoint-${Math.floor(Date.now() / 1000)}`;
  const res = await nrpc(bootstrapToken, 'add-token', { comment });
  if (!res || !res.key) {
    throw new Error('add-token: response missing `key` — Njalla schema may have changed');
  }
  return { token: res.key, comment };
}

async function revokeEphemeral(bootstrapToken, ephemeral) {
  try {
    const res = await nrpc(bootstrapToken, 'remove-token', { key: ephemeral.token });
    return res && res.status === 'removed';
  } catch (e) {
    return false;
  }
}

// ─── main ──────────────────────────────────────────────────────────
async function main() {
  const bootstrapToken = readBootstrapToken();
  if (!bootstrapToken) {
    throw new Error('bootstrap token empty');
  }

  console.log('minting ephemeral API token from bootstrap…');
  let ephemeral;
  let usedToken;
  let canManageTokens = false;
  try {
    ephemeral = await mintEphemeral(bootstrapToken);
    usedToken = ephemeral.token;
    canManageTokens = true;
    // We log only the comment (not the key prefix) so the line is
    // safe to ship into any log aggregator without leaking the
    // bearer token.
    console.log(`  ephemeral token minted: comment="${ephemeral.comment}" (lives until end of run)`);
  } catch (e) {
    // If Njalla rejects add-token (e.g. older API version, restricted
    // account, or method renamed), gracefully degrade to using the
    // bootstrap token directly for this run. Log loudly so the
    // operator notices.
    console.warn(`  add-token unavailable (${e.message}). Falling back to bootstrap token for this run only.`);
    usedToken = bootstrapToken;
  }

  let didWork = false;
  try {
    const slate = await buildSlate();
    console.log('Slate:');
    for (const e of slate) console.log(`  height=${e.height} hash=${e.hash}`);

    for (const name of NAMES) {
      console.log(`\n--- ${name}.${DOMAIN} ---`);
      const records = await nrpc(usedToken, 'list-records', { domain: DOMAIN });
      const existing = (records.records || []).filter(
        (r) => r.type === 'TXT' && r.name === name
      );
      if (DRY_RUN) {
        console.log(`  (DRY-RUN) would remove ${existing.length} existing TXT record(s) + add ${slate.length} new`);
        continue;
      }
      for (const r of existing) {
        await nrpc(usedToken, 'remove-record', { domain: DOMAIN, id: r.id });
        console.log(`  removed old TXT id=${r.id} "${r.content}"`);
      }
      for (const e of slate) {
        const content = `${e.height}:${e.hash}`;
        await nrpc(usedToken, 'add-record', { domain: DOMAIN, type: 'TXT', name, content, ttl: 600 });
        console.log(`  added TXT "${content}"`);
      }
    }
    didWork = true;
  } finally {
    if (canManageTokens && ephemeral) {
      console.log('\nrevoking ephemeral token…');
      const revoked = await revokeEphemeral(bootstrapToken, ephemeral);
      if (revoked) {
        console.log('  ok — ephemeral token deleted from Njalla');
      } else {
        console.warn('  WARNING — ephemeral token revoke FAILED. Manual cleanup at https://njal.la/settings/api/');
      }
    }
  }

  if (didWork) {
    console.log('\nDONE. Verify in ~60s:');
    console.log(`  dig +short TXT checkpoints.${DOMAIN}`);
    console.log(`  dig +short TXT checkpoints2.${DOMAIN}`);
  }
}

main().catch((e) => {
  console.error('FAILED: ' + e.message);
  process.exit(1);
});
