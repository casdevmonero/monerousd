#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// ─────────────────────────────────────────────────────────────────
// verify-phishing-manifest.js — local pre-upload sanity check
//
// Runs the same Ed25519 verify path the desktop wallet's
// `verifyPhishingSignature` uses (build-1261/main.js). Operator
// runs this AFTER signing to catch a mismatched-pubkey before
// uploading to update.monerousd.org and shipping a manifest the
// fleet will reject.
//
// Usage:
//   node scripts/verify-phishing-manifest.js \
//     --manifest phishing.json \
//     --pubkey   <64-hex>
//
// Exits 0 on success, non-zero on any verification failure.
// ─────────────────────────────────────────────────────────────────

const fs     = require('node:fs');
const crypto = require('node:crypto');

const args = {};
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a === '--manifest') args.manifest = process.argv[++i];
  else if (a === '--pubkey')   args.pubkey   = process.argv[++i];
}
if (!args.manifest || !args.pubkey) {
  console.error('Usage: --manifest <json> --pubkey <hex>');
  process.exit(2);
}
if (!/^[0-9a-fA-F]{64}$/.test(args.pubkey)) {
  console.error('pubkey must be 64 hex chars');
  process.exit(2);
}

const parsed = JSON.parse(fs.readFileSync(args.manifest, 'utf8'));
if (!Array.isArray(parsed.origins)) {
  console.error('manifest missing origins[]');
  process.exit(2);
}
if (!Number.isFinite(parsed.version) || !Number.isFinite(parsed.issued_at)) {
  console.error('manifest missing version or issued_at');
  process.exit(2);
}
if (typeof parsed.signature !== 'string' || parsed.signature.length !== 128) {
  console.error('signature missing or wrong length');
  process.exit(2);
}

const canonical = JSON.stringify({
  origins:   parsed.origins,
  version:   parsed.version,
  issued_at: parsed.issued_at,
});
const data   = Buffer.from(canonical, 'utf8');
const sig    = Buffer.from(parsed.signature, 'hex');
const pubKey = Buffer.from(args.pubkey, 'hex');
const SPKI   = Buffer.from('302a300506032b6570032100', 'hex');

const keyObj = crypto.createPublicKey({
  key:    Buffer.concat([SPKI, pubKey]),
  format: 'der',
  type:   'spki',
});

if (!crypto.verify(null, data, keyObj, sig)) {
  console.error('SIGNATURE INVALID — wallet will reject this manifest');
  process.exit(1);
}

console.log('OK — manifest verifies against the supplied pubkey');
console.log('  origins:   ' + parsed.origins.length);
console.log('  version:   ' + parsed.version);
console.log('  issued:    ' + new Date(parsed.issued_at).toISOString());
const ageMs = Date.now() - parsed.issued_at;
const ageDays = Math.round(ageMs / 86400000);
console.log('  age:       ' + ageDays + 'd');
if (ageDays > 25) {
  console.warn('  WARN: manifest is ' + ageDays + 'd old; wallets reject ' +
    '> 30d. Re-sign before upload.');
}
