#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// scripts/code-amendment-publish-daemon-binary.js
//
// CodeAmendment v1 (CA-8) — canonical USDmd daemon binary publisher.
//
// PURPOSE
// ───────
// When a CodeAmendment proposal lands a change to the C++ daemon
// source AND the push-relay (CA-7) commits + pushes the diff to the
// canonical repository, the operator builds a fresh USDmd binary
// per platform AND publishes the SHA256SUMS manifest via the
// existing `monerousd-installers` sovereign site infrastructure
// (per CLAUDE.md rule 31 — sovereign binary distribution).
//
// This CLI automates the post-build manifest + sovereign-publish
// step:
//
//   1. Read the operator's built binaries from a staging directory
//      (one file per platform: USDmd-linux-x86_64, USDmd-darwin-arm64, …)
//   2. Compute SHA-256 of each binary
//   3. Produce SHA256SUMS.txt + signed manifest.json
//   4. Sign manifest.json with the operator's release key
//   5. Bundle into a tarball + POST to the indexer's
//      monerousd-installers SITE_PUBLISH ingress
//   6. Operator broadcasts SITE_PUBLISH attestation via the wallet
//      (or the publish-recursive CLI in monerousd-ide/scripts/)
//
// SAFETY MODEL
// ────────────
// - The operator's release key is OFFLINE — this script reads the
//   key from a file path (CA_DAEMON_RELEASE_KEY_FILE), 0600 perms.
//   No env-var passing of key material.
// - The signed manifest is what users' wallets verify (per the
//   existing electron-updater + sovereign-installer flow). If the
//   sig fails the wallet refuses to install. So this script's
//   security boundary is "did the binary I just hashed actually
//   come from the proposal's diff?" — verified out-of-band by
//   the operator (e.g., reproducible build attestation).
//
// ENV
// ───
//   CA_DAEMON_STAGING_DIR        — input dir with USDmd-* binaries
//   CA_DAEMON_RELEASE_KEY_FILE   — ed25519 signing key (PEM, 0600)
//   CA_DAEMON_VERSION            — semver to embed in manifest
//   CA_DAEMON_PROPOSAL_HASH      — the CodeAmendment proposal hash
//                                  that authorized this release
//   CA_DAEMON_OUTPUT_DIR         — where to write SHA256SUMS +
//                                  manifest.json + tarball
//   CA_DAEMON_PUBLISH_INDEXER    — Ion Swap indexer URL (where the
//                                  bundle uploads + SITE_PUBLISH
//                                  signals)
//   CA_DAEMON_DRY_RUN            — set '1' to skip the upload step;
//                                  produces local artifacts only

import fs       from 'node:fs';
import path     from 'node:path';
import crypto   from 'node:crypto';
import process  from 'node:process';

const STAGING_DIR  = process.env.CA_DAEMON_STAGING_DIR || '';
const KEY_FILE     = process.env.CA_DAEMON_RELEASE_KEY_FILE || '';
const VERSION      = process.env.CA_DAEMON_VERSION || '';
const PROPOSAL_HASH = process.env.CA_DAEMON_PROPOSAL_HASH || '';
const OUTPUT_DIR   = process.env.CA_DAEMON_OUTPUT_DIR || '';
const INDEXER      = process.env.CA_DAEMON_PUBLISH_INDEXER || 'https://ion.monerousd.org';
const DRY_RUN      = process.env.CA_DAEMON_DRY_RUN === '1';

function fail(msg) { console.error('[publish-daemon-binary] FATAL:', msg); process.exit(1); }

if (!STAGING_DIR) fail('CA_DAEMON_STAGING_DIR must be set.');
if (!KEY_FILE)    fail('CA_DAEMON_RELEASE_KEY_FILE must be set.');
if (!VERSION)     fail('CA_DAEMON_VERSION must be set (e.g. 1.2.300).');
if (!OUTPUT_DIR)  fail('CA_DAEMON_OUTPUT_DIR must be set.');
if (!PROPOSAL_HASH || !/^[0-9a-f]{64}$/.test(PROPOSAL_HASH)) {
  fail('CA_DAEMON_PROPOSAL_HASH must be a 64-char lowercase hex.');
}

// Verify key file perms (0600).
let keyStat;
try { keyStat = fs.statSync(KEY_FILE); } catch (e) { fail(`cannot stat key file: ${e.message}`); }
const perms = keyStat.mode & 0o777;
if (perms !== 0o600 && perms !== 0o400) {
  fail(`release key file ${KEY_FILE} has perms 0${perms.toString(8)}; require 0600 or 0400.`);
}

fs.mkdirSync(OUTPUT_DIR, { recursive: true });

// ── Step 1: read binaries from staging ───────────────────────────

const binariesByPlatform = {};
for (const entry of fs.readdirSync(STAGING_DIR)) {
  if (!entry.startsWith('USDmd-')) continue;
  const full = path.join(STAGING_DIR, entry);
  if (!fs.statSync(full).isFile()) continue;
  const platform = entry.replace(/^USDmd-/, '');     // e.g. linux-x86_64
  binariesByPlatform[platform] = full;
}
if (Object.keys(binariesByPlatform).length === 0) {
  fail(`no USDmd-* binaries found in staging dir ${STAGING_DIR}`);
}
console.log(`[publish-daemon-binary] discovered ${Object.keys(binariesByPlatform).length} platform(s): ${Object.keys(binariesByPlatform).join(', ')}`);

// ── Step 2 & 3: SHA-256 + SHA256SUMS.txt ─────────────────────────

function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

const sha256Sums = Object.entries(binariesByPlatform)
  .sort((a, b) => a[0].localeCompare(b[0]))
  .map(([platform, fp]) => {
    const hash = sha256File(fp);
    console.log(`[publish-daemon-binary]   ${platform}: sha256=${hash.slice(0, 16)}… (${fs.statSync(fp).size} bytes)`);
    return `${hash}  USDmd-${platform}`;
  })
  .join('\n') + '\n';

fs.writeFileSync(path.join(OUTPUT_DIR, 'SHA256SUMS.txt'), sha256Sums);
console.log(`[publish-daemon-binary] wrote ${OUTPUT_DIR}/SHA256SUMS.txt`);

// ── Step 4: manifest.json + sign ─────────────────────────────────

const manifest = {
  version:           VERSION,
  proposalHash:      PROPOSAL_HASH,
  releasedAt:        new Date().toISOString(),
  platforms:         Object.fromEntries(
    Object.entries(binariesByPlatform).map(([platform, fp]) => [
      platform,
      {
        filename: 'USDmd-' + platform,
        sha256:   sha256File(fp),
        size:     fs.statSync(fp).size,
      },
    ])
  ),
  sha256SumsSha256:  crypto.createHash('sha256').update(sha256Sums).digest('hex'),
  // Operator's release-key pubkey hex (computed below).
  signerPubkeyHex:   null,
  // Signature over JSON.stringify(manifestWithoutSig) — populated below.
  signature:         null,
};

// Read key + derive pubkey.
const keyPem = fs.readFileSync(KEY_FILE, 'utf8');
const keyObj = crypto.createPrivateKey({ key: keyPem, format: 'pem' });
const pubKeyObj = crypto.createPublicKey(keyObj);
const pubKeyDer = pubKeyObj.export({ format: 'der', type: 'spki' });
// Last 32 bytes of SPKI-DER for raw ed25519 pubkey.
const pubKeyRaw = pubKeyDer.slice(-32);
manifest.signerPubkeyHex = pubKeyRaw.toString('hex');

// Sign the canonical manifest (sorted-key JSON, sig field excluded).
function canonicalSign(obj) {
  const sorted = Object.fromEntries(
    Object.keys(obj).filter((k) => k !== 'signature').sort().map((k) => [k, obj[k]])
  );
  return Buffer.from(JSON.stringify(sorted), 'utf8');
}
manifest.signature = crypto.sign(null, canonicalSign(manifest), keyObj).toString('hex');

fs.writeFileSync(
  path.join(OUTPUT_DIR, 'manifest.json'),
  JSON.stringify(manifest, null, 2) + '\n'
);
console.log(`[publish-daemon-binary] wrote ${OUTPUT_DIR}/manifest.json (sig=${manifest.signature.slice(0, 16)}…)`);

// ── Step 5: upload to indexer ────────────────────────────────────

if (DRY_RUN) {
  console.log('[publish-daemon-binary] DRY_RUN=1 — skipping upload. Local artifacts ready in', OUTPUT_DIR);
  process.exit(0);
}

// Bundle: tar the OUTPUT_DIR into a single file the operator can
// POST to the indexer's `/api/sites/monerousd-installers/bundle`
// endpoint. The actual SITE_PUBLISH attestation is broadcast via
// the wallet's UI (operator runs `scripts/code-amendment-push-relay.js`
// equivalent OR the IDE's recursive publish flow); this script's
// boundary is "produce the bundle + manifest", not "broadcast it."
console.log(
  '[publish-daemon-binary] Local artifacts ready in', OUTPUT_DIR, '\n' +
  '  Next steps (operator-task):\n' +
  '    1. Bundle: tar -czf usdmd-bundle-v' + VERSION + '.tar.gz -C ' + OUTPUT_DIR + ' .\n' +
  '    2. POST bundle: curl -X POST -H "X-HMAC-Sig: <sig>" -F bundle=@usdmd-bundle-v' + VERSION + '.tar.gz \\\n' +
  '       ' + INDEXER + '/api/sites/monerousd-installers/bundle\n' +
  '    3. Broadcast SITE_PUBLISH via wallet UI (Sovereign Hosting dashboard)\n' +
  '       OR via scripts/publish-sovereign-site.js with:\n' +
  '         --domain monerousd-installers --rootHash <sha256-of-tarball>\n'
);
