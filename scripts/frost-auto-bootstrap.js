#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/* scripts/frost-auto-bootstrap.js
 *
 * One-time deterministic FROST bootstrap. Replaces the multi-party
 * DKG2 ceremony (docs/FROST-QUORUM-PROVISIONING-RUNBOOK.md) with a
 * single-host key generation flow so the substrate can ship NOW —
 * then a real DKG2 ceremony rotates the keys later via a wallet
 * release.
 *
 * What this script does
 * ─────────────────────
 *   1. Generates 3 ed25519 keypairs locally (Node's crypto):
 *        DAEMON_BINARIES, PEER_MANIFEST, CHAIN_SNAPSHOT
 *   2. Saves PRIVATE keys to ~/.monerousd/frost-bootstrap-keys.json
 *      (mode 0o600, operator-secret).
 *   3. Saves PUBLIC keys to ~/.monerousd/frost-bootstrap-pubkeys.json
 *      (public, used in test fixtures).
 *   4. Patches build-1261/lib/frost-quorum-verifier.js to replace the
 *      all-zero placeholders with the real pubkeys.
 *   5. Exposes a sign helper: --sign-manifest --purpose --in --out
 *      so the operator can sign real manifests without invoking the
 *      multi-party ceremony.
 *
 * Security tradeoff (transparent)
 * ───────────────────────────────
 *   • Single-host bootstrap = single-key-compromise = full forge.
 *   • Acceptable for the v0 substrate launch since:
 *       - No user has any manifests signed by this key yet
 *       - The keys can be rotated via a wallet release at any time
 *       - The DKG2 ceremony (multi-party) is the path forward
 *   • The bootstrap keys MUST live ONLY on the operator's secure host
 *     (not in a public repo, not on the VPS, not in any backup that
 *     leaves the operator's control).
 *
 * Usage
 * ─────
 *   # Initial bootstrap (run ONCE per operator deployment):
 *   node scripts/frost-auto-bootstrap.js init
 *
 *   # Sign a manifest:
 *   node scripts/frost-auto-bootstrap.js sign \
 *     --purpose DAEMON_BINARIES \
 *     --in /tmp/manifest.json \
 *     --out /tmp/manifest.sig.hex
 *
 *   # Print pubkeys (for docs / fixtures):
 *   node scripts/frost-auto-bootstrap.js pubkeys
 *
 *   # Verify a signature locally (round-trip self-test):
 *   node scripts/frost-auto-bootstrap.js selftest
 *
 *   # Show current bootstrap state (does it exist? when?):
 *   node scripts/frost-auto-bootstrap.js status
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const PURPOSES = ['DAEMON_BINARIES', 'PEER_MANIFEST', 'CHAIN_SNAPSHOT'];

const KEYS_DIR        = path.join(os.homedir(), '.monerousd');
const PRIV_PATH       = path.join(KEYS_DIR, 'frost-bootstrap-keys.json');
const PUB_PATH        = path.join(KEYS_DIR, 'frost-bootstrap-pubkeys.json');
const VERIFIER_PATH   = path.resolve(__dirname, '..',
                          'build-1261', 'lib', 'frost-quorum-verifier.js');

// ─── Crypto helpers ─────────────────────────────────────────────

function genKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  // raw 32-byte public key (strip the SPKI DER prefix at the end).
  const rawPub  = publicKey.export({ format: 'der', type: 'spki' }).slice(-32);
  // PKCS8 private key (the canonical Node form, used for signing).
  const pkcs8Priv = privateKey.export({ format: 'pem', type: 'pkcs8' });
  return { rawPub: rawPub.toString('hex'), pkcs8Priv };
}

function canonicalize(payload) {
  // Must byte-equal build-1261/lib/frost-quorum-verifier.js::canonicalize.
  // Sorted-keys JSON + trailing LF.
  const sorted = JSON.stringify(payload, function (_k, v) {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const out = {};
      for (const k of Object.keys(v).sort()) out[k] = v[k];
      return out;
    }
    return v;
  });
  return Buffer.from(sorted + '\n', 'utf8');
}

function sign(manifest, privKeyPem) {
  const canonical = canonicalize(manifest);
  const sig = crypto.sign(null, canonical, crypto.createPrivateKey(privKeyPem));
  return sig.toString('hex');
}

function verify(manifest, sigHex, rawPubHex) {
  const canonical = canonicalize(manifest);
  const pubkey = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(rawPubHex, 'hex'),
    ]),
    format: 'der',
    type: 'spki',
  });
  return crypto.verify(null, canonical, pubkey, Buffer.from(sigHex, 'hex'));
}

// ─── Subcommands ────────────────────────────────────────────────

function cmdInit({ force = false } = {}) {
  fs.mkdirSync(KEYS_DIR, { recursive: true });
  if (fs.existsSync(PRIV_PATH) && !force) {
    console.error('error: ' + PRIV_PATH + ' already exists.');
    console.error('       use --rotate to replace (existing keys archived).');
    process.exit(2);
  }
  if (fs.existsSync(PRIV_PATH) && force) {
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    fs.renameSync(PRIV_PATH, PRIV_PATH + '.rotated-' + ts);
    fs.renameSync(PUB_PATH,  PUB_PATH  + '.rotated-' + ts);
    console.log('rotated existing keys aside with suffix .rotated-' + ts);
  }

  const priv = {};
  const pub = {};
  for (const purpose of PURPOSES) {
    const kp = genKeypair();
    priv[purpose] = { pkcs8: kp.pkcs8Priv, created_at: new Date().toISOString() };
    pub[purpose]  = { pubkey_hex: kp.rawPub, created_at: priv[purpose].created_at };
  }

  fs.writeFileSync(PRIV_PATH, JSON.stringify(priv, null, 2), { mode: 0o600 });
  fs.chmodSync(PRIV_PATH, 0o600);
  fs.writeFileSync(PUB_PATH,  JSON.stringify(pub,  null, 2));

  patchVerifier(pub);
  console.log('OK');
  console.log('  private keys: ' + PRIV_PATH + '  (mode 0600, OPERATOR-SECRET)');
  console.log('  public keys:  ' + PUB_PATH);
  console.log('  patched:      ' + VERIFIER_PATH);
  console.log('');
  console.log('Pubkeys:');
  for (const purpose of PURPOSES) {
    console.log('  ' + purpose.padEnd(16) + '  ' + pub[purpose].pubkey_hex);
  }
}

function patchVerifier(pub) {
  if (!fs.existsSync(VERIFIER_PATH)) {
    console.error('error: verifier source not found at ' + VERIFIER_PATH);
    process.exit(3);
  }
  let src = fs.readFileSync(VERIFIER_PATH, 'utf8');
  for (const purpose of PURPOSES) {
    // Match BOTH the placeholder shape (`'0'.repeat(64)`) AND the
    // already-patched shape (`'<64-hex>'`). Use [^,)]* non-greedy
    // inside the first arg + then `, 'hex')` so we don't bite
    // off the inner `)` of `repeat(64)`.
    const reBoth = new RegExp(
      `${purpose}:\\s*Buffer\\.from\\(` +
      `(?:'0'\\.repeat\\(64\\)|'[0-9a-f]{64}')` +
      `,\\s*'hex'\\)`,
      'g'
    );
    if (!reBoth.test(src)) {
      console.error('error: ' + purpose + ' placeholder not found in verifier');
      console.error('       expected one of:');
      console.error('         ' + purpose + ": Buffer.from('0'.repeat(64), 'hex')");
      console.error('         ' + purpose + ": Buffer.from('<64-hex>', 'hex')");
      process.exit(4);
    }
    // Reset the regex's lastIndex for the replace pass.
    const reReplace = new RegExp(
      `${purpose}:\\s*Buffer\\.from\\(` +
      `(?:'0'\\.repeat\\(64\\)|'[0-9a-f]{64}')` +
      `,\\s*'hex'\\)`,
    );
    const pubHex = pub[purpose].pubkey_hex;
    src = src.replace(reReplace,
      `${purpose}: Buffer.from('${pubHex}', 'hex')`
    );
  }
  fs.writeFileSync(VERIFIER_PATH, src);
}

function cmdSign(argv) {
  const purpose = argFlag(argv, '--purpose');
  const inPath  = argFlag(argv, '--in');
  const outPath = argFlag(argv, '--out');
  if (!purpose || !inPath || !outPath) {
    console.error('usage: sign --purpose <PURPOSE> --in <manifest.json> --out <sig.hex>');
    process.exit(2);
  }
  if (!PURPOSES.includes(purpose)) {
    console.error('error: --purpose must be one of: ' + PURPOSES.join(', '));
    process.exit(2);
  }
  if (!fs.existsSync(PRIV_PATH)) {
    console.error('error: bootstrap keys not found at ' + PRIV_PATH);
    console.error('       run `init` first.');
    process.exit(2);
  }
  const priv = JSON.parse(fs.readFileSync(PRIV_PATH, 'utf8'));
  const manifest = JSON.parse(fs.readFileSync(inPath, 'utf8'));
  const sigHex = sign(manifest, priv[purpose].pkcs8);
  fs.writeFileSync(outPath, sigHex);
  console.log('signed.');
  console.log('  manifest:  ' + inPath);
  console.log('  signature: ' + outPath);
  console.log('  purpose:   ' + purpose);
  console.log('  sig (hex): ' + sigHex);
}

function cmdPubkeys() {
  if (!fs.existsSync(PUB_PATH)) {
    console.error('error: no bootstrap; run `init` first.');
    process.exit(2);
  }
  const pub = JSON.parse(fs.readFileSync(PUB_PATH, 'utf8'));
  for (const purpose of PURPOSES) {
    console.log(purpose + ':  ' + pub[purpose].pubkey_hex);
  }
}

function cmdSelftest() {
  if (!fs.existsSync(PRIV_PATH)) {
    console.error('error: no bootstrap; run `init` first.');
    process.exit(2);
  }
  const priv = JSON.parse(fs.readFileSync(PRIV_PATH, 'utf8'));
  const pub  = JSON.parse(fs.readFileSync(PUB_PATH, 'utf8'));

  let allOk = true;
  for (const purpose of PURPOSES) {
    const sampleManifest = {
      purpose,
      version: 1,
      timestamp: new Date().toISOString(),
      content: 'frost-bootstrap-selftest',
    };
    const sigHex = sign(sampleManifest, priv[purpose].pkcs8);
    const verifyOk = verify(sampleManifest, sigHex, pub[purpose].pubkey_hex);
    if (verifyOk) {
      console.log('OK  ' + purpose + '  (sign+verify round-trip)');
    } else {
      console.log('FAIL ' + purpose + '  (verify failed)');
      allOk = false;
    }
    // Adversarial test: flip one byte; must fail.
    const tampered = { ...sampleManifest, content: 'tampered' };
    const verifyTampered = verify(tampered, sigHex, pub[purpose].pubkey_hex);
    if (!verifyTampered) {
      console.log('OK  ' + purpose + '  (tampered-payload rejected)');
    } else {
      console.log('FAIL ' + purpose + '  (tampered-payload ACCEPTED — verifier broken)');
      allOk = false;
    }
  }
  process.exit(allOk ? 0 : 1);
}

function cmdStatus() {
  if (!fs.existsSync(PRIV_PATH)) {
    console.log('NOT BOOTSTRAPPED');
    process.exit(1);
  }
  const stat = fs.statSync(PRIV_PATH);
  const pub  = JSON.parse(fs.readFileSync(PUB_PATH, 'utf8'));
  console.log('BOOTSTRAPPED at ' + pub[PURPOSES[0]].created_at);
  console.log('  private keys: ' + PRIV_PATH + '  (mode ' + (stat.mode & 0o777).toString(8) + ')');
  console.log('  public keys:  ' + PUB_PATH);
  for (const purpose of PURPOSES) {
    console.log('  ' + purpose.padEnd(16) + '  ' + pub[purpose].pubkey_hex.slice(0, 16) + '…');
  }
}

// ─── arg helpers ───────────────────────────────────────────────

function argFlag(argv, name) {
  const i = argv.indexOf(name);
  if (i < 0) return null;
  return argv[i + 1];
}
function hasFlag(argv, name) {
  return argv.includes(name);
}

// ─── main ───────────────────────────────────────────────────────

function main(argv) {
  const cmd = argv[0];
  switch (cmd) {
    case 'init':
      cmdInit({ force: hasFlag(argv, '--rotate') || hasFlag(argv, '--force') });
      break;
    case 'sign':
      cmdSign(argv.slice(1));
      break;
    case 'pubkeys':
      cmdPubkeys();
      break;
    case 'selftest':
      cmdSelftest();
      break;
    case 'status':
      cmdStatus();
      break;
    default:
      console.error('usage:');
      console.error('  frost-auto-bootstrap.js init    [--rotate]');
      console.error('  frost-auto-bootstrap.js sign    --purpose <P> --in <manifest.json> --out <sig.hex>');
      console.error('  frost-auto-bootstrap.js pubkeys');
      console.error('  frost-auto-bootstrap.js selftest');
      console.error('  frost-auto-bootstrap.js status');
      process.exit(2);
  }
}

main(process.argv.slice(2));
