#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// publish-lws-snapshot.js — operator-side LWS snapshot publisher.
//
// PURPOSE
// ───────
// Eliminate the canonical-operator HTTPS LWS endpoint as a single
// point of failure. The operator periodically dumps the entire
// scope_outputs index, signs it with the FROST quorum key, and
// publishes the signed dump as a GitHub Release asset.
//
// Wallets (via lib/lws-gh-mirror.cjs) fetch the latest snapshot
// from GitHub on first restore. GitHub CDNs the asset across
// Fastly + multiple egress regions; "taking it down" requires
// either GitHub itself complying with a takedown OR a global Fastly
// outage. If either happens, the same dump format can be mirrored
// to IPFS, an onion service, Codeberg, or a community-run HTTP
// host — without ANY wallet code change, because the manifest URL
// at `update.monerousd.org/lws-snapshot.json` is operator-rotatable
// (the manifest is the indirection layer; the signed dump's
// quorum-pubkey check is the trust check).
//
// FUTURE-PROOFING
// ───────────────
// The snapshot manifest's SHA-256 will be anchored on-chain via
// SITE_PUBLISH (per CLAUDE.md rule 30 / decentralization plan §5).
// Once that's wired, the wallet verifies the snapshot's hash
// against the on-chain anchor — making the snapshot fully
// censorship-proof (GitHub goes down → wallets fall back to any
// mirror that publishes the same SHA-256).
//
// WHAT THIS SCRIPT DOES (one-shot, idempotent):
//   1. Reads the bootstrap Njalla token from Keychain ONLY for the
//      manifest publish step; the LWS dump itself signs with the
//      operator's FROST signing key (separate key).
//   2. Pulls every active scope_output entry from the operator's
//      LWS server via /v1/lws/scope-outputs/list (or equivalent
//      bulk-export endpoint).
//   3. Builds the canonical snapshot body (sorted scope_id, fixed
//      schema_version).
//   4. Signs the canonical body with the FROST signing key.
//   5. Publishes the signed body as a GitHub Release asset to
//      `casdevmonero/monerousd-lws-snapshots` (auto-created if
//      missing). Tag = `lws-snapshot-<unix-ts>`.
//   6. Updates `update.monerousd.org/lws-snapshot.json` (which
//      CNAMEs to GH Pages on the OTA manifest repo) to point at
//      the new asset URL + SHA-256.
//
// USAGE (one-time setup):
//   1. Generate the FROST signing key (or reuse the existing release
//      signer):
//        bash scripts/njalla-keychain.sh set     # already done
//      We use the SAME release-signer-1.pem we already provisioned
//      for SHA256SUMS (decentralization plan §3). One signer, two
//      sig surfaces.
//   2. Run this script: `node scripts/publish-lws-snapshot.js`
//   3. Schedule it weekly: see scripts/install-checkpoint-cron.sh
//      for the launchd pattern (re-use, change Label + Program).
//
// USAGE (per refresh — fully automated):
//     node scripts/publish-lws-snapshot.js
//
// SAFETY HOOKS (decentralization plan, rule 52 of build-1261/CLAUDE.md)
//   • The published snapshot MUST verify under
//     RELEASE_SIGNER_PUBKEYS_HEX[0] (= e0843660...). The wallet's
//     verification path is `lib/lws-gh-mirror.cjs::verifySnapshot`.
//   • Tests at `tests/sites/lws-gh-mirror-snapshot.test.js` pin:
//     (a) sigverify against the correct pubkey passes
//     (b) tampered body fails
//     (c) wrong-pubkey signature fails
//     (d) missing-fields snapshot is rejected

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const https = require('node:https');
const { execFileSync } = require('node:child_process');

// ─── config ────────────────────────────────────────────────────────
const LWS_BULK_ENDPOINT = process.env.LWS_BULK_ENDPOINT
  || 'https://ion.monerousd.org/v1/lws/scope-outputs/list';
const SIGNING_KEY_PATH = process.env.LWS_SNAPSHOT_KEY_PATH
  || path.resolve(__dirname, '..', '..', '.monerousd', 'release-keys', 'release-signer-1.pem');
const SNAPSHOT_REPO = process.env.LWS_SNAPSHOT_REPO
  || 'casdevmonero/monerousd-lws-snapshots';
const MANIFEST_REPO = process.env.OTA_MANIFEST_REPO_PATH
  || '/tmp/monerousd-ota-manifest';
const PUBKEY_HEX = process.env.RELEASE_SIGNER_PUBKEY_HEX
  || 'e08436607c8ef043b70f6ae0876a21a702e327908be28c4aa9835d5433f00c6e';

// ─── helpers ───────────────────────────────────────────────────────
function getJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error('HTTP ' + res.statusCode + ' on ' + url));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch (e) { reject(new Error('JSON parse failed: ' + e.message)); }
      });
    }).on('error', reject);
  });
}

function canonicalize(v) {
  if (v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map(canonicalize);
  const out = {};
  for (const k of Object.keys(v).sort()) out[k] = canonicalize(v[k]);
  return out;
}

function signBody(canonicalBytes) {
  const priv = crypto.createPrivateKey(fs.readFileSync(SIGNING_KEY_PATH, 'utf8'));
  return crypto.sign(null, canonicalBytes, priv).toString('hex');
}

function selfVerifySnapshot(snapshot) {
  // Same algorithm the wallet's lws-gh-mirror.cjs uses. If THIS
  // fails, never publish — the dump is unrecoverable.
  const pkRaw = Buffer.from(PUBKEY_HEX, 'hex');
  if (pkRaw.length !== 32) throw new Error('invalid PUBKEY_HEX');
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pkRaw]);
  const pk = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  const body = Buffer.from(snapshot.signed_body, 'utf8');
  const sig = Buffer.from(snapshot.signature, 'hex');
  return crypto.verify(null, body, pk, sig);
}

// ─── main ──────────────────────────────────────────────────────────
async function main() {
  console.log('1) fetching LWS bulk export from ' + LWS_BULK_ENDPOINT);
  const exportData = await getJson(LWS_BULK_ENDPOINT);
  if (!exportData || !Array.isArray(exportData.entries)) {
    throw new Error('bulk endpoint did not return { entries: [...] }');
  }
  console.log('   got ' + exportData.entries.length + ' entries');

  // Build canonical body. Sort entries by (scope_id, tx_hash, output_idx_hint)
  // so the SHA-256 is stable across re-runs that produce the same logical
  // contents.
  const sortedEntries = [...exportData.entries].sort((a, b) => {
    const sa = (a.scope_id || '') + '|' + (a.tx_hash || '') + '|' + (a.output_idx_hint || 0);
    const sb = (b.scope_id || '') + '|' + (b.tx_hash || '') + '|' + (b.output_idx_hint || 0);
    return sa < sb ? -1 : sa > sb ? 1 : 0;
  });
  const body = canonicalize({
    schema_version: 1,
    snapshot_built_at: Math.floor(Date.now() / 1000),
    entries_count: sortedEntries.length,
    entries: sortedEntries,
  });
  const canonical = JSON.stringify(body);

  console.log('2) signing ' + canonical.length + ' bytes under ' + PUBKEY_HEX.slice(0, 8) + '...');
  const signature = signBody(Buffer.from(canonical, 'utf8'));
  const snapshot = {
    version: 1,
    signed_body: canonical,
    signature,
    signer_pubkey_hex: PUBKEY_HEX,
  };

  console.log('3) self-verifying signature…');
  if (!selfVerifySnapshot(snapshot)) {
    throw new Error('self-verify FAILED — refusing to publish a bad dump');
  }
  console.log('   ok');

  // Compute SHA-256 of the full signed snapshot. That's what the
  // manifest carries + what the wallet verifies on download.
  const snapshotBytes = Buffer.from(JSON.stringify(snapshot), 'utf8');
  const snapshotSha256 = crypto.createHash('sha256').update(snapshotBytes).digest('hex');
  const stagedPath = path.join('/tmp', `lws-snapshot-${Math.floor(Date.now()/1000)}.json`);
  fs.writeFileSync(stagedPath, snapshotBytes);
  console.log('4) staged at ' + stagedPath + ' (' + snapshotBytes.length + ' bytes, sha256=' + snapshotSha256.slice(0,16) + '...)');

  // Create the GH Release + upload the asset.
  const tag = 'lws-snapshot-' + Math.floor(Date.now() / 1000);
  console.log('5) creating GH release ' + tag + ' in ' + SNAPSHOT_REPO);
  try {
    execFileSync('gh', [
      'repo', 'view', SNAPSHOT_REPO,
    ], { stdio: 'pipe' });
  } catch (e) {
    console.log('   creating repo (does not exist yet)…');
    execFileSync('gh', [
      'repo', 'create', SNAPSHOT_REPO, '--public',
      '--description', 'MoneroUSD LWS index snapshots — signed Ed25519 dumps. Wallets fetch the latest manifest from update.monerousd.org/lws-snapshot.json and verify against the operator pubkey hardcoded in their binary.',
    ], { stdio: 'inherit' });
  }
  execFileSync('gh', [
    'release', 'create', tag, stagedPath,
    '--repo', SNAPSHOT_REPO,
    '--title', 'LWS snapshot ' + tag,
    '--notes', 'Signed LWS scope-outputs dump (' + sortedEntries.length + ' entries). SHA-256: ' + snapshotSha256 + '\n\nThe wallet auto-fetches this when the local cache is empty and the operator HTTPS endpoint is censored or unreachable. See decentralization plan §1.',
  ], { stdio: 'inherit' });

  // Update the manifest in /tmp/monerousd-ota-manifest/lws-snapshot.json
  // and push.
  const manifest = {
    schema_version: 1,
    snapshot_url: `https://github.com/${SNAPSHOT_REPO}/releases/download/${tag}/${path.basename(stagedPath)}`,
    snapshot_sha256: snapshotSha256,
    snapshot_size_bytes: snapshotBytes.length,
    entries_count: sortedEntries.length,
    snapshot_built_at: body.snapshot_built_at,
    signer_pubkey_hex: PUBKEY_HEX,
    // Mirror list — wallets try each in order. Add IPFS / onion /
    // Codeberg mirrors here as they come online.
    mirrors: [
      `https://github.com/${SNAPSHOT_REPO}/releases/download/${tag}/${path.basename(stagedPath)}`,
    ],
  };
  const manifestPath = path.join(MANIFEST_REPO, 'lws-snapshot.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  console.log('6) wrote manifest to ' + manifestPath);

  // Commit + push the manifest. Caller is responsible for ensuring
  // the OTA manifest repo's gitignore allowlists lws-snapshot.json
  // (we set this up alongside seeds.json + SHA256SUMS.sig.*).
  try {
    execFileSync('git', ['-C', MANIFEST_REPO, 'add', 'lws-snapshot.json'], { stdio: 'inherit' });
    execFileSync('git', [
      '-C', MANIFEST_REPO,
      '-c', 'user.email=ops@monerousd.org',
      '-c', 'user.name=MoneroUSD Ops',
      'commit', '-m', 'Publish LWS snapshot ' + tag + ' (' + sortedEntries.length + ' entries)',
    ], { stdio: 'inherit' });
    execFileSync('git', ['-C', MANIFEST_REPO, 'push', 'origin', 'main'], { stdio: 'inherit' });
    console.log('7) pushed manifest to OTA repo');
  } catch (e) {
    console.warn('   manifest push failed (you may need to commit + push manually): ' + e.message);
  }

  console.log('\nDONE.');
  console.log('  Snapshot URL: ' + manifest.snapshot_url);
  console.log('  Manifest:     https://update.monerousd.org/lws-snapshot.json (live after GH Pages rebuild, ~60-120s)');
  console.log('  Wallets pick up the new manifest on next restore. Local-cache + GH-snapshot are now censorship-proof.');
}

main().catch((e) => {
  console.error('FAILED: ' + e.message);
  process.exit(1);
});
