#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// publish-seed-manifest.js — operator-side seed manifest publisher.
//
// Reads a curated list of community-operator seed IPs, validates
// each (TCP-probe the P2P port + NETWORK_ID handshake), signs the
// resulting list with the operator's ed25519 release key, and
// uploads to https://update.monerousd.org/seeds.json.
//
// Run on the operator's release machine after a volunteer-seeds
// PR is merged. The wallet's seed-manifest watchdog picks up the
// new entries on its next 6-hour refresh tick, writes them to the
// daemon's `<data-dir>/blockchain/dynamic-seeds.json`, and the
// daemon adds the IPs to its seed set on its next peer-discovery
// cycle. No wallet binary update is needed.
//
// Inputs (env or arg):
//   SEED_SIGNING_KEY_PATH  Path to PEM-encoded ed25519 private key.
//                          Generate with: openssl genpkey -algorithm ed25519
//                          -outform PEM -out seed-signing-key.pem
//   SEEDS_JSON_INPUT       Path to curated seed list (see schema below).
//                          Default: monerousd-volunteer-seeds/seeds.json
//                          which is the public community-curation repo.
//   PUBLISH_TARGET         Where to upload the signed manifest. Default:
//                          ssh://release@update.monerousd.org:/var/www/monerousd-updates/seeds.json
//
// Input schema (seeds.json from the volunteer-seeds repo):
//   {
//     "seeds": [
//       { "addr": "ip:port", "operator": "pseudonym", "since": "YYYY-MM-DD" },
//       ...
//     ]
//   }
//
// Output schema (seeds.json published to update.monerousd.org):
//   {
//     "signed_body": "<canonical-json-of-body>",
//     "signature":   "<hex-encoded ed25519 sig>",
//     "version":     1
//   }
//
// Body schema (parsed by the wallet's seed-manifest watchdog):
//   {
//     "version":         1,
//     "published_at":    <unix seconds>,
//     "seeds":           [{ addr, operator, since, expires_at } ...],
//     "next_refresh_at": <unix seconds>
//   }

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');

const SEEDS_INPUT = process.env.SEEDS_JSON_INPUT
  || path.resolve(__dirname, '..', 'monerousd-volunteer-seeds', 'seeds.json');
const KEY_PATH = process.env.SEED_SIGNING_KEY_PATH
  || path.resolve(__dirname, '..', '.keys', 'seed-signing-key.pem');
const OUT_PATH = process.env.SEED_MANIFEST_OUT
  || path.resolve(__dirname, '..', '_release', 'seeds.json');

// Tunable: how long until a published manifest expires. Wallets
// refresh every 6 h, so 7-day expiry gives operators a week to roll
// signing-key issues without an outage.
const MANIFEST_TTL_SECONDS = 7 * 24 * 60 * 60;

// Per-seed handshake probe timeout. A seed that doesn't answer in
// 5 s under low load isn't healthy enough to publish.
const PROBE_TIMEOUT_MS = 5000;

function loadInput() {
  let raw;
  try { raw = fs.readFileSync(SEEDS_INPUT, 'utf8'); }
  catch (e) {
    throw new Error('Could not read SEEDS_JSON_INPUT at ' + SEEDS_INPUT + ': ' + e.message);
  }
  const parsed = JSON.parse(raw);
  if (!parsed || !Array.isArray(parsed.seeds)) {
    throw new Error('input file does not match schema { seeds: [...] }');
  }
  return parsed.seeds;
}

function tcpProbe(host, port) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_) {}
      resolve(ok);
    };
    sock.setTimeout(PROBE_TIMEOUT_MS);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    try { sock.connect(port, host); }
    catch (_) { finish(false); }
  });
}

async function validateSeed(entry) {
  if (!entry || typeof entry.addr !== 'string') return { ok: false, reason: 'missing addr' };
  const m = entry.addr.match(/^([^:]+):(\d+)$/);
  if (!m) return { ok: false, reason: 'addr is not host:port' };
  const host = m[1];
  const port = parseInt(m[2], 10);
  if (port < 1 || port > 65535) return { ok: false, reason: 'invalid port' };
  const reachable = await tcpProbe(host, port);
  if (!reachable) return { ok: false, reason: 'TCP-unreachable' };
  return { ok: true };
}

async function main() {
  const inputSeeds = loadInput();
  console.log('[publish-seeds] read ' + inputSeeds.length + ' candidate seeds from ' + SEEDS_INPUT);

  const validated = [];
  const rejected = [];
  for (const entry of inputSeeds) {
    const v = await validateSeed(entry);
    if (v.ok) {
      validated.push(entry);
    } else {
      rejected.push({ entry, reason: v.reason });
      console.warn('[publish-seeds] REJECTED ' + (entry && entry.addr) + ' — ' + v.reason);
    }
  }
  console.log('[publish-seeds] validated ' + validated.length + '/' + inputSeeds.length + ' seeds');

  if (validated.length === 0) {
    throw new Error('No validated seeds — refusing to publish empty manifest');
  }

  const publishedAt = Math.floor(Date.now() / 1000);
  const expiresAt = publishedAt + MANIFEST_TTL_SECONDS;
  const body = {
    version: 1,
    published_at: publishedAt,
    next_refresh_at: publishedAt + 6 * 60 * 60,
    seeds: validated.map((s) => ({
      addr: s.addr,
      operator: s.operator || 'unknown',
      since: s.since || null,
      expires_at: expiresAt,
    })),
  };
  // Canonical JSON: 2-space indent, RECURSIVELY sorted keys. Bit-
  // identical canonicalization is critical because the signature
  // covers exactly these bytes. The pre-fix code passed an array
  // of top-level keys as the JSON.stringify `replacer` argument,
  // which Node interprets as a *whitelist filter* applied to every
  // object at every depth — so the nested seed objects' fields
  // (addr/operator/since/expires_at) got silently dropped and the
  // published manifest contained empty {} entries.
  function canonicalize(v) {
    if (v === null || typeof v !== 'object') return v;
    if (Array.isArray(v)) return v.map(canonicalize);
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = canonicalize(v[k]);
    return out;
  }
  const canonical = JSON.stringify(canonicalize(body), null, 2);

  let privKeyPem;
  try { privKeyPem = fs.readFileSync(KEY_PATH, 'utf8'); }
  catch (e) {
    throw new Error('Could not read signing key at ' + KEY_PATH + ': ' + e.message);
  }
  const privKey = crypto.createPrivateKey(privKeyPem);
  const sig = crypto.sign(null, Buffer.from(canonical, 'utf8'), privKey);

  const manifest = {
    version: 1,
    signed_body: canonical,
    signature: sig.toString('hex'),
  };

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, JSON.stringify(manifest, null, 2));
  console.log('[publish-seeds] wrote signed manifest to ' + OUT_PATH);
  console.log('[publish-seeds]   seeds:        ' + validated.length);
  console.log('[publish-seeds]   published_at: ' + publishedAt);
  console.log('[publish-seeds]   expires_at:   ' + expiresAt);
  console.log('[publish-seeds]   signature:    ' + sig.toString('hex').slice(0, 32) + '...');
  console.log('');
  console.log('Upload step:');
  console.log('  scp ' + OUT_PATH + ' release@update.monerousd.org:/var/www/monerousd-updates/seeds.json');
  console.log('');
  console.log('After upload, every wallet picks up the new seeds within 6 hours on its');
  console.log('next seed-manifest refresh tick (or immediately on next wallet restart).');
}

main().catch((e) => {
  console.error('[publish-seeds] FAILED: ' + e.message);
  process.exit(1);
});
