#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// ─────────────────────────────────────────────────────────────────────
// release-binary-broadcast.js
//
// Phase H release-coordinator CLI for the MoneroUSD desktop wallet.
// Builds a `BINARY_RELEASE` manifest from a set of per-platform
// binaries, ML-DSA-65-signs the canonical commitment, and emits a
// payload the operator can paste into their wallet's Release-Publish
// wizard so the standard `walletBroadcast` pipeline handles the
// approval modal + carrier tx + chain anchor.
//
// Why this script exists
// ----------------------
// Pre-Phase-H, releases were the last load-bearing VPS dependency:
// `https://update.monerousd.org/...` was the single source of binary
// truth. Anyone who controlled that URL could push a malicious
// build. Phase H closes that with a chain-anchored SHA + multi-mirror
// download:
//
//   1. Coordinator runs THIS script on any machine — laptop, CI
//      runner, community-validator host. No VPS required.
//   2. Script hashes every per-platform binary, builds the manifest,
//      signs it with the coordinator's release key (Phase H1 — single
//      ML-DSA-65 seed) or a PQ-FROST quorum ceremony (future decentralization).
//   3. Coordinator pastes the emitted attestation payload into their
//      wallet's BINARY_RELEASE broadcast handler — `walletBroadcast`
//      shows the standard approval modal so the coordinator authorizes
//      the chain action with a fee + carrier tx like any other op.
//   4. The wallet's chain-scanner picks up the BINARY_RELEASE
//      attestation, `binary-release-verifier.js` checks the signature,
//      `isBinaryStale` compares chain-anchored SHA vs local, and
//      `downloadBinary` walks the mirror list verifying each candidate
//      against the chain anchor before accepting it.
//
// What this script DOES NOT do
// ----------------------------
// • It does not broadcast on its own. Per the wallet's hard rule 1
//   ("every write goes through `walletBroadcast()`"), the actual chain
//   broadcast happens inside the operator's wallet via the standard
//   approval flow.
// • It does not push binaries anywhere. `--upload-dir` writes a local
//   directory the operator can rsync to whichever mirrors they run.
//   The chain-anchored SHA is the trust root; the URLs are advisory.
// • It does not produce reproducible builds. That's a separate
//   workstream (see `docs/DECENTRALIZED-BINARY-RELEASE.md` §5).
//
// Usage
// -----
//   node scripts/release-binary-broadcast.js \
//     --name USDmd \
//     --version 1.2.211 \
//     --signing-key ./release-keys/mldsa-seed.hex \
//     --linux-x64    ./build/linux-x64/USDmd \
//     --mac-arm64    ./build/mac-arm64/USDmd \
//     --mac-x64      ./build/mac-x64/USDmd \
//     --windows-x64  ./build/windows-x64/USDmd.exe \
//     --source-commit $(git rev-parse HEAD) \
//     --mirror https://update.monerousd.org/bin/\${platform}/\${name} \
//     --mirror https://mirror.example-validator.org/usdmd/\${version}/\${platform}/\${name} \
//     --out ./out/binary-release-1.2.211.json
//
// Exit codes
// ----------
//   0  manifest built + signed, broadcast payload written
//   1  bad args / missing files
//   2  hashing or signing failure
// ─────────────────────────────────────────────────────────────────────

'use strict';

const fs     = require('node:fs');
const path   = require('node:path');
const crypto = require('node:crypto');

// Hard-link to the wallet's verifier so this script and the wallet
// produce byte-identical canonical signing bytes. Drift between
// signer + verifier == catastrophic; binding to one source eliminates
// the drift class entirely.
const VERIFIER_PATH = path.join(
  __dirname, '..', 'build-1261', 'lib', 'binary-release-verifier.js'
);
let _canonicalMessage;
try {
  ({ _canonicalMessage } = require(VERIFIER_PATH));
} catch (e) {
  console.error('FATAL: cannot load wallet verifier at ' + VERIFIER_PATH);
  console.error('       ' + (e && e.message || e));
  process.exit(2);
}

// ─── Platform table ──────────────────────────────────────────────────
//
// Mirrors `binary-release-verifier.js::detectPlatform` exactly. The
// CLI accepts a `--<platform>` flag for each entry, so adding a new
// platform takes ONE table edit + bumping the verifier in lockstep.

const PLATFORMS = [
  'linux-x64',
  'linux-arm64',
  'mac-x64',
  'mac-arm64',
  'windows-x64',
  'windows-arm64',
];

// ─── arg parsing ─────────────────────────────────────────────────────

function usageAndExit(code) {
  console.error(
    'Usage: release-binary-broadcast \\\n' +
    '         --name <USDmd|USDm-wallet-rpc> \\\n' +
    '         --version <semver> \\\n' +
    '         --signing-key <pem-file | hex-file> \\\n' +
    '         --<platform> <binary-path>     (one or more)\\\n' +
    '         [--source-commit <git-sha>]\\\n' +
    '         [--build-meta-key value ...]\\\n' +
    '         [--mirror <url-template> ...]\\\n' +
    '         [--out <broadcast-payload.json>]\\\n' +
    '         [--upload-dir <dir>]\\\n' +
    '         [--quiet]\n\n' +
    'Platforms: ' + PLATFORMS.join(', ') + '\n\n' +
    'Mirror URL templates may contain ${platform}, ${name}, ${version}\n' +
    'tokens — wallets substitute them at download time. Trust comes\n' +
    'from the chain-anchored SHA, not the URL.\n'
  );
  process.exit(code);
}

function parseArgs(argv) {
  const out = {
    binaries:    {},  // platform → binary path
    buildMeta:   {},
    mirrors:     [],
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--name')           out.name           = argv[++i];
    else if (a === '--version')   out.version        = argv[++i];
    else if (a === '--signing-key') out.signingKey   = argv[++i];
    else if (a === '--source-commit') out.sourceCommit = argv[++i];
    else if (a === '--mirror')    out.mirrors.push(argv[++i]);
    else if (a === '--out')       out.outPath        = argv[++i];
    else if (a === '--upload-dir') out.uploadDir     = argv[++i];
    else if (a === '--quiet')     out.quiet          = true;
    else if (a === '-h' || a === '--help') out.help  = true;
    else if (a.startsWith('--build-meta-')) {
      const key = a.slice('--build-meta-'.length);
      const val = argv[++i];
      if (!key) usageAndExit(1);
      out.buildMeta[key] = val;
    } else if (a.startsWith('--')) {
      const platform = a.slice(2);
      if (PLATFORMS.includes(platform)) {
        out.binaries[platform] = argv[++i];
      } else {
        console.error('unknown flag: ' + a);
        usageAndExit(1);
      }
    } else {
      console.error('unexpected arg: ' + a);
      usageAndExit(1);
    }
  }
  return out;
}

const args = parseArgs(process.argv);
if (args.help) usageAndExit(0);
if (!args.name || !args.version || !args.signingKey) usageAndExit(1);
if (Object.keys(args.binaries).length === 0) {
  console.error('at least one --<platform> <path> required');
  usageAndExit(1);
}
if (!/^[A-Za-z0-9._-]+$/.test(args.name)) {
  console.error('--name contains illegal characters');
  usageAndExit(1);
}
if (!/^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9._-]+)?$/.test(args.version)) {
  console.error('--version must be semver (e.g. 1.2.211 or 1.2.211-rc.1)');
  usageAndExit(1);
}

// ─── per-binary hash ─────────────────────────────────────────────────

function hashFile(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error('binary not found: ' + filePath);
  }
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) {
    throw new Error('not a file: ' + filePath);
  }
  const h = crypto.createHash('sha256');
  const buf = fs.readFileSync(filePath);
  h.update(buf);
  return { sha256: h.digest('hex'), size: buf.length };
}

// ─── POST-QUANTUM (ML-DSA-65) signing ────────────────────────────────
//
// The signing key is a 32-byte hex seed (one hex line in a text file); the
// ML-DSA-65 keypair (FIPS 204) is derived deterministically from it. The
// matching 1952-byte public key is written next to the manifest output so the
// operator bakes it into the wallet binary at the next build via
// `WALLET_BINARY_RELEASE_PUBKEY`. Same post-quantum primitive the wallet's
// binary-release-verifier + peer-manifest + daemon-binary verifiers use — a
// Shor-breakable signature over "which binary to spawn" is a Pillar-2 violation.

const mldsa = require('../build-1261/lib/mldsa-liboqs-binding.cjs');

function loadSigningKey(keyPath) {
  if (!fs.existsSync(keyPath)) {
    throw new Error('signing key not found: ' + keyPath);
  }
  const hex = fs.readFileSync(keyPath, 'utf8').trim().replace(/\s+/g, '');
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('signing key file must be a 64-hex-char (32-byte) ML-DSA-65 seed');
  }
  // Deterministic ML-DSA-65 keypair from the 32-byte seed.
  return mldsa.generateKeypairFromSeed(Buffer.from(hex, 'hex'));
}

function pubkeyHexFromPrivate(kp) {
  // The 1952-byte ML-DSA-65 public key — baked into WALLET_BINARY_RELEASE_PUBKEY
  // so the wallet's verifier checks releases against it.
  return Buffer.from(kp.publicKey).toString('hex');
}

function mldsaSign(messageBytes, kp) {
  // ML-DSA-65 signature (3309 bytes) over the canonical release commitment.
  return Buffer.from(mldsa.sign(kp.secretKey, messageBytes)).toString('hex');
}

// ─── main ────────────────────────────────────────────────────────────

(async function main() {
  const log = args.quiet ? () => {} : (...m) => console.error(...m);

  // 1) hash every per-platform binary
  const binaries = {};
  for (const platform of Object.keys(args.binaries).sort()) {
    const p = path.resolve(args.binaries[platform]);
    log(`  hashing ${platform} ${p}`);
    let entry;
    try { entry = hashFile(p); }
    catch (e) {
      console.error('hash failed: ' + (e && e.message || e));
      process.exit(2);
    }
    binaries[platform] = entry;
  }

  // 2) build the manifest body — `binaries` keys sorted so the wire
  // shape is deterministic.
  const manifest = {
    name:    args.name,
    version: args.version,
    binaries,
  };
  if (args.sourceCommit) manifest.source_commit = args.sourceCommit;
  if (Object.keys(args.buildMeta).length) {
    manifest.build_meta = args.buildMeta;
  }
  if (args.mirrors.length) manifest.mirrors = args.mirrors.slice();

  // 3) canonical-encode + sign — `_canonicalMessage` is the wallet's
  // verifier, so signer + verifier produce byte-identical bytes by
  // construction.
  let signingKey, signatureHex, pubkeyHex;
  try {
    signingKey   = loadSigningKey(args.signingKey);
    pubkeyHex    = pubkeyHexFromPrivate(signingKey);
    const msg    = _canonicalMessage(manifest);
    signatureHex = mldsaSign(msg, signingKey);
  } catch (e) {
    console.error('signing failed: ' + (e && e.message || e));
    process.exit(2);
  }

  manifest.signature = signatureHex;

  // 4) build the broadcast payload — ready to feed into the wallet's
  // BINARY_RELEASE provider method (or paste into the Release wizard).
  // Carrier tx is a 1-atomic pure-signature transfer per rule 47.
  const broadcast = {
    code: 'BINARY_RELEASE',
    payload: manifest,
    pubkeyHex,
    note:
      'Open the wallet → Settings → Release → Broadcast Manifest, paste ' +
      'this JSON. The wallet will encode it as ion://op/v1?code=BINARY_RELEASE, ' +
      'route it through walletBroadcast (rule 1), show the approval modal, ' +
      'and broadcast a 1-atomic carrier tx per rule 47.',
  };

  // 5) emit. stdout is the default sink so the operator can pipe
  // straight into a wallet RPC; --out also writes a file for record.
  const payloadJson = JSON.stringify(broadcast, null, 2) + '\n';
  if (args.outPath) {
    const abs = path.resolve(args.outPath);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, payloadJson, 'utf8');
    log(`  wrote ${abs}`);
    // Pubkey side-car so the operator can baked it into the wallet
    // build at WALLET_BINARY_RELEASE_PUBKEY env time.
    const sidecar = abs.replace(/\.json$/, '') + '.pubkey.txt';
    fs.writeFileSync(sidecar, pubkeyHex + '\n', 'utf8');
    log(`  wrote ${sidecar}`);
  } else {
    process.stdout.write(payloadJson);
  }

  // 6) optional: copy the binaries themselves into a directory the
  // operator can rsync to whichever mirrors they run. Layout matches
  // the default mirror URL template `${platform}/${name}` so a plain
  // static-file server works out of the box.
  if (args.uploadDir) {
    const root = path.resolve(args.uploadDir);
    for (const platform of Object.keys(args.binaries)) {
      const dest = path.join(root, args.version, platform, args.name);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(path.resolve(args.binaries[platform]), dest);
      log(`  copied → ${dest}`);
    }
    // SHA256SUMS for human verification — chain-anchored SHA still
    // reigns, but a hand-checked sums file is a useful belt-and-
    // suspenders artifact.
    const sumsPath = path.join(root, args.version, 'SHA256SUMS');
    const sumsLines = Object.keys(binaries).sort().map(p =>
      `${binaries[p].sha256}  ${p}/${args.name}`
    );
    fs.writeFileSync(sumsPath, sumsLines.join('\n') + '\n', 'utf8');
    log(`  wrote ${sumsPath}`);
  }

  log('');
  log('  release pubkey (set WALLET_BINARY_RELEASE_PUBKEY at next wallet build):');
  log('    ' + pubkeyHex);
  log('');
  log(`  ${args.name} ${args.version} — signed manifest ready to broadcast`);
})().catch(e => {
  console.error('release-binary-broadcast: ' + (e && e.stack || e));
  process.exit(2);
});
