#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// ─────────────────────────────────────────────────────────────────
// Operator-side CLI: refund a stuck failed attestation
// ─────────────────────────────────────────────────────────────────
//
// One-shot tool to issue a refund through the HMAC-gated
// `POST /api/admin/attestation/refund-stuck` endpoint added in the
// 2026-05-16 WOJ audit follow-up. Reads the admin HMAC secret from
// `/etc/ion/admin.hmac` (the canonical operator-only secret file
// per CLAUDE.md rule 73), signs the request, and posts.
//
// Run ON THE VPS — the HMAC secret stays on the VPS by design.
// Stale callers anywhere else can't authenticate.
//
// Usage (on VPS):
//   node refund-failed-attestation-cli.js <txHash> [--expect-dest <stealth>]
//
// Example for the WOJ stuck-LP incident:
//   node refund-failed-attestation-cli.js \
//     6a2e9640ca24e06c3dbf36452d653ebf31f5140f9ff8985c6031f417e3e4395b
//
// The refund target is taken from the staged payload's
// `creatorStealth` field. The optional `--expect-dest` flag adds a
// safety check that the staged stealth matches what the operator
// expected — useful when reconciling an incident report.
//
// Idempotent: if the refund already executed (a prior run of this
// tool, or the auto-refund path landed), the endpoint returns
// `alreadyRefunded: true` with the original refund tx hash.

'use strict';

const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const http = require('http');

// Mirror of the server-side `_loadAdminHmacKey()` convention
// (backend/server.js _ADMIN_HMAC_KEY_FILE / _ADMIN_HMAC_KEY_DIRECT).
// Key file is read as a TRIMMED utf8 STRING and passed directly to
// createHmac — NOT hex-decoded. Any conversion here desyncs from
// the server and every request signs with the wrong key.
const HMAC_FILES = [
  process.env.ION_BRIDGE_ADMIN_HMAC_KEY_FILE,
  '/etc/ion/admin.hmac',
  '/etc/ion/admin.hmac.key',
  process.env.ION_ADMIN_HMAC_FILE,
].filter(Boolean);

const ENDPOINTS = [
  process.env.ION_API_BASE || 'http://127.0.0.1:7777',
  'https://ion.monerousd.org',
];

function readHmacKey() {
  // Env-var override first (server reads ION_BRIDGE_ADMIN_HMAC_KEY
  // directly when set with no file).
  if (process.env.ION_BRIDGE_ADMIN_HMAC_KEY) return process.env.ION_BRIDGE_ADMIN_HMAC_KEY.trim();
  for (const path of HMAC_FILES) {
    try {
      const stat = fs.statSync(path);
      if ((stat.mode & 0o077) !== 0) {
        console.warn(`[refund] WARN: ${path} mode is ${stat.mode.toString(8)} — should be 0600`);
      }
      const raw = fs.readFileSync(path, 'utf8').trim();
      if (raw) return raw;
    } catch (_) { /* try next */ }
  }
  throw new Error(`Could not read admin HMAC key from any of: ${HMAC_FILES.join(', ')}`);
}

function hmacSign({ key, ts, method, path, body }) {
  // Server convention: HMAC challenge = `${ts}\n${method}\n${path}\n${body}`.
  // Key is the raw trimmed file content (string), not hex-decoded.
  // `ts` is MILLISECONDS (server compares to Date.now()).
  const challenge = `${ts}\n${method}\n${path}\n${body}`;
  return crypto.createHmac('sha256', key).update(challenge).digest('hex');
}

async function postAdmin({ base, path, body }) {
  const url = new URL(path, base);
  const bodyStr = body ? JSON.stringify(body) : '';
  const ts = Date.now();                              // ms — server uses Date.now()
  const key = readHmacKey();
  const sig = hmacSign({ key, ts, method: 'POST', path: url.pathname, body: bodyStr });

  const isHttps = url.protocol === 'https:';
  const lib = isHttps ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request({
      method: 'POST',
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(bodyStr),
        'x-ion-admin-ts': String(ts),
        'x-ion-admin-sig': sig,
      },
    }, (res) => {
      let chunks = '';
      res.on('data', (c) => { chunks += c; });
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(chunks); } catch { /* leave raw */ }
        resolve({ status: res.statusCode, body: parsed || chunks });
      });
    });
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args[0].startsWith('-')) {
    console.error('Usage: node refund-failed-attestation-cli.js <txHash> [--expect-dest <stealth>]');
    process.exit(2);
  }
  const txHash = args[0].toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(txHash)) {
    console.error('Error: txHash must be 64 hex chars (got: ' + args[0] + ')');
    process.exit(2);
  }
  let expectDest = null;
  const i = args.indexOf('--expect-dest');
  if (i >= 0 && args[i + 1]) expectDest = args[i + 1];

  const body = { tx_hash: txHash };
  if (expectDest) body.expect_dest = expectDest;

  let lastErr = null;
  for (const base of ENDPOINTS) {
    try {
      console.log(`[refund] POST ${base}/api/admin/attestation/refund-stuck`);
      const res = await postAdmin({ base, path: '/api/admin/attestation/refund-stuck', body });
      console.log(`[refund] HTTP ${res.status}`);
      console.log(JSON.stringify(res.body, null, 2));
      if (res.status >= 200 && res.status < 300) {
        process.exit(0);
      }
      // Non-2xx — try the next endpoint only on transport-level failure;
      // 4xx is a real error from the backend and should not be retried.
      if (res.status >= 400 && res.status < 500) process.exit(1);
      lastErr = new Error('HTTP ' + res.status);
    } catch (e) { lastErr = e; }
  }
  console.error('[refund] All endpoints failed: ' + (lastErr && lastErr.message));
  process.exit(1);
}

main().catch((e) => {
  console.error('[refund] FATAL:', e.message);
  process.exit(1);
});
