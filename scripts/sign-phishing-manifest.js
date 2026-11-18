#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// ─────────────────────────────────────────────────────────────────
// sign-phishing-manifest.js — Ed25519 sign the dApp phishing list
//
// What this is
//   The wallet's main process (`build-1261/main.js`) hard-blocks
//   dApp connect attempts from origins listed in
//   `phishing.json` served from `update.monerousd.org`. Per
//   build-1261/CLAUDE.md §C1 / S6, the list MUST be Ed25519-signed
//   so a compromised CDN edge or rogue TLS cert can't push a list
//   that removes known-bad sites (or DOSes legit ones).
//
//   This script is the operator-side counterpart: it reads the
//   plaintext origin list, attaches `version` + `issued_at`, signs
//   with the offline-held Ed25519 private key, and writes the
//   final `phishing.json` ready for upload to update.monerousd.org.
//
// Trust model
//   The privkey lives in cold storage. This script runs on a
//   cold/air-gapped machine. The VERIFIED public key is pinned in
//   `build-1261/main.js::PHISHING_SIGN_PUBKEY` and ships in every
//   wallet binary. The wallet REJECTS any manifest whose signature
//   doesn't verify against that pubkey, doesn't bear a monotonic
//   `version`, or is older than 30 days — fail-closed in every
//   direction.
//
// Usage
//   node scripts/sign-phishing-manifest.js \
//     --privkey ~/cold/phishing-sign.privkey.pem \
//     --origins origins.txt \
//     --version 7 \
//     --out phishing.json
//
//   Where `origins.txt` is one origin per line (e.g.
//   `https://malicious-site.example`). Lines starting with `#`
//   are treated as comments and skipped.
//
// Keygen (FIRST TIME ONLY — run once on the cold machine):
//   openssl genpkey -algorithm Ed25519 -out phishing-sign.privkey.pem
//   openssl pkey -in phishing-sign.privkey.pem -pubout -outform DER \
//     | tail -c 32 | xxd -p -c 64
//   # The last line is the 64-hex pubkey to pin in
//   # build-1261/main.js::PHISHING_SIGN_PUBKEY.
//
// Versioning
//   `version` MUST monotonically increase across every upload.
//   The wallet rejects any incoming version < last-stored version
//   (downgrade-attack defense). Pick the previous version + 1
//   each time. The script will refuse a value < the previous
//   `_last-version.txt` it wrote (script-side defense).
//
// Signature contract
//   The wallet verifies a signature over:
//
//     JSON.stringify({ origins, version, issued_at })
//
//   with sorted-key serialization NOT REQUIRED — the canonical
//   bytes here MUST match exactly what the wallet's
//   `verifyPhishingSignature` reads. The script + the verifier
//   are the single source of truth for that shape; if you change
//   it here, change `verifyPhishingSignature` in main.js in the
//   same commit + bump the version field.
// ─────────────────────────────────────────────────────────────────

const fs     = require('node:fs');
const path   = require('node:path');
const crypto = require('node:crypto');

// ── arg parsing ────────────────────────────────────────────────
function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--privkey')      out.privkey  = argv[++i];
    else if (a === '--origins') out.origins  = argv[++i];
    else if (a === '--version') out.version  = Number(argv[++i]);
    else if (a === '--out')     out.outPath  = argv[++i];
    else if (a === '--help' || a === '-h') {
      console.log(fs.readFileSync(__filename, 'utf8')
        .split('\n').filter((l) => l.startsWith('//')).join('\n'));
      process.exit(0);
    } else {
      console.error('Unknown arg: ' + a);
      process.exit(2);
    }
  }
  return out;
}

const args = parseArgs(process.argv);
if (!args.privkey || !args.origins || !args.outPath) {
  console.error('Usage: node sign-phishing-manifest.js ' +
    '--privkey <pem> --origins <txt> [--version <N>] --out <json>');
  process.exit(2);
}
if (!Number.isFinite(args.version)) {
  // Auto-bump from sidecar file if version omitted.
  const sidecar = path.join(path.dirname(args.outPath), '_last-version.txt');
  let last = 0;
  try { last = Number(fs.readFileSync(sidecar, 'utf8').trim()) || 0; } catch (_) {}
  args.version = last + 1;
  console.warn('[sign-phishing] auto-bumped version to ' + args.version +
    ' (last was ' + last + ')');
}

// ── load + sanity-check origins ────────────────────────────────
function loadOrigins(file) {
  const raw  = fs.readFileSync(file, 'utf8');
  const list = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    // Sanity — every entry should look like an origin.
    if (!/^https?:\/\/[^\/\s]+$/.test(trimmed)) {
      console.warn('[sign-phishing] WARNING: origin "' + trimmed +
        '" doesn\'t match `^https?://host$` — including anyway, ' +
        'but the wallet may not match it');
    }
    list.push(trimmed);
  }
  // Stable sort for determinism — easier review of diffs across releases.
  list.sort();
  return list;
}

const origins = loadOrigins(args.origins);
if (origins.length === 0) {
  console.error('[sign-phishing] origins file is empty after stripping ' +
    'blank/comment lines — refusing to sign an empty manifest');
  process.exit(2);
}

// ── version monotonicity sidecar check ─────────────────────────
const sidecarPath = path.join(path.dirname(args.outPath), '_last-version.txt');
let storedLastVersion = 0;
try {
  storedLastVersion = Number(fs.readFileSync(sidecarPath, 'utf8').trim()) || 0;
} catch (_) { /* no sidecar yet */ }
if (args.version <= storedLastVersion) {
  console.error('[sign-phishing] version ' + args.version +
    ' is not greater than the previous signed version ' + storedLastVersion +
    '. The wallet will reject this manifest as a downgrade attack.');
  process.exit(2);
}

// ── load privkey ───────────────────────────────────────────────
let privKey;
try {
  const pem = fs.readFileSync(args.privkey, 'utf8');
  privKey = crypto.createPrivateKey({ key: pem, format: 'pem' });
  if (privKey.asymmetricKeyType !== 'ed25519') {
    console.error('[sign-phishing] privkey is not Ed25519 (got: ' +
      privKey.asymmetricKeyType + ')');
    process.exit(2);
  }
} catch (e) {
  console.error('[sign-phishing] could not load privkey at ' + args.privkey +
    ': ' + (e.message || e));
  process.exit(2);
}

// ── canonical bytes + sign ─────────────────────────────────────
const issuedAt = Date.now();
const canonicalObj = { origins, version: args.version, issued_at: issuedAt };
const canonical    = JSON.stringify(canonicalObj);
const signature    = crypto.sign(null, Buffer.from(canonical, 'utf8'), privKey);
if (signature.length !== 64) {
  // Defensive — Node's Ed25519 always returns 64 bytes; bail loudly
  // if anything ever drifts.
  console.error('[sign-phishing] signature length unexpected: ' + signature.length);
  process.exit(2);
}

const manifest = {
  ...canonicalObj,
  signature: signature.toString('hex'),
};

// ── write output + sidecar ─────────────────────────────────────
fs.writeFileSync(args.outPath, JSON.stringify(manifest, null, 2) + '\n');
fs.writeFileSync(sidecarPath, String(args.version) + '\n');

console.log('[sign-phishing] wrote ' + args.outPath);
console.log('  origins:  ' + origins.length);
console.log('  version:  ' + args.version);
console.log('  issued:   ' + new Date(issuedAt).toISOString());
console.log('  size:     ' + fs.statSync(args.outPath).size + ' bytes');
console.log('');
console.log('Next steps:');
console.log('  1. Verify locally:');
console.log('     node scripts/verify-phishing-manifest.js ' +
  '--manifest ' + args.outPath + ' --pubkey <hex>');
console.log('  2. scp to edge:');
console.log('     scp ' + args.outPath +
  ' root@$MONEROUSD_EDGE_HOST:/var/www/monerousd-updates/phishing.json');
console.log('  3. Verify the wallet picks it up next refresh (within 1h).');
