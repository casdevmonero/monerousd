#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/* scripts/founder-sign-proposal.js
 *
 * CLI that signs a CodeAmendment v1 proposal payload with the
 * founder identity. The resulting `founderSig` hex gets pasted into
 * the proposal payload's `founderSig` field before the user clicks
 * "Broadcast" in the wallet's wizard. Verification happens client-
 * side in every wallet (via build-1261/lib/founder-pubkeys.js) and
 * server-side in the indexer (via the same pinned constants).
 *
 * Runs LOCALLY on the founder's secure machine — same trust model as
 * scripts/founder-bootstrap.js. NEVER expose this via the wallet UI.
 *
 * Pipeline:
 *
 *   1. Wallet's CodeAmendment wizard collects + validates the
 *      CODE_PROPOSE payload, computes the proposal hash via the
 *      shared canonicalizer (build-1261/lib/code-amendment-codec.js
 *      ::computeProposalHash), and shows it to the founder.
 *
 *   2. Founder runs:
 *        node scripts/founder-sign-proposal.js \
 *          --wallet-rpc-url http://127.0.0.1:27750 \
 *          --version v1 \
 *          --payload-file /tmp/proposal.json
 *
 *      where /tmp/proposal.json is the canonical payload exported
 *      from the wallet (creatorStealthSig + creatorStealthSigOpId
 *      + founderSig fields ALL absent — the canonicalizer strips
 *      them before signing anyway, but the file is the pre-sign
 *      shape).
 *
 *   3. CLI:
 *        a. Re-derives the founder's HKDF ed25519 keypair from the
 *           wallet's spend_key (same derivation as bootstrap)
 *        b. Reads the payload JSON from disk
 *        c. Canonicalizes via the shared canonicalizer
 *        d. Signs the canonical bytes with the ed25519 private key
 *        e. Prints the 128-hex sig to STDOUT
 *
 *   4. Founder copies the hex into the wallet's wizard "founder
 *      signature (paste here)" field; the wizard verifies the sig
 *      against the pinned FOUNDER_PUBKEYS[CURRENT_VERSION] before
 *      enabling the Broadcast button.
 *
 * STDOUT is a single line:
 *   founder_sig: <128-hex>
 *
 * STDERR carries progress + errors only. Never logs payload contents,
 * spend_key, or the wallet address.
 *
 * Hard rules:
 *   - Per CLAUDE.md rule 49 — no silent fallbacks. If the CLI can't
 *     verify the resulting sig against the locally-derived pubkey, it
 *     refuses to print and exits non-zero.
 *   - Payload size is capped at 32 KB (the CODE_PROPOSE encoder caps
 *     diff bytes at 2 MB but the payload itself stays small — diffs
 *     ride out-of-band via the off-chain bundle endpoint, rule 12).
 */

'use strict';

const crypto = require('node:crypto');
const fs     = require('node:fs');
const path   = require('node:path');
const http   = require('node:http');
const { URL } = require('node:url');

// ── Shared canonicalizer (must match the wallet's lib mirror) ────

const AUTH_FIELDS_TO_STRIP = Object.freeze([
  'creatorStealthSig',
  'creatorStealthSigOpId',
  'founderSig',
]);

function canonicalizeForHash(parsedPayload) {
  if (!parsedPayload || typeof parsedPayload !== 'object') {
    throw new Error('canonicalizeForHash: payload required');
  }
  const sorter = (_k, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const sorted = {};
      for (const k of Object.keys(v).sort()) {
        if (AUTH_FIELDS_TO_STRIP.includes(k)) continue;
        sorted[k] = v[k];
      }
      return sorted;
    }
    return v;
  };
  const stripped = {};
  for (const k of Object.keys(parsedPayload).sort()) {
    if (AUTH_FIELDS_TO_STRIP.includes(k)) continue;
    stripped[k] = parsedPayload[k];
  }
  return Buffer.from(JSON.stringify(stripped, sorter) + '\n', 'utf8');
}

// ── HKDF identical to founder-bootstrap.js ──────────────────────

const HKDF_DOMAIN_PREFIX = 'monerousd-founder-tag-';
const HKDF_OUTPUT_LEN    = 32;
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function deriveFounderKeypair(spendPrivHex, version) {
  if (!/^[0-9a-f]{64}$/.test(spendPrivHex)) {
    throw new Error('spend_priv from wallet-rpc is not 64-char hex');
  }
  if (!/^v[1-9][0-9]*$/.test(version)) {
    throw new Error('version must be vN where N >= 1');
  }
  const ikm  = Buffer.from(spendPrivHex, 'hex');
  const salt = Buffer.alloc(0);
  const info = Buffer.from(HKDF_DOMAIN_PREFIX + version, 'utf8');
  // hkdfSync returns ArrayBuffer in current Node versions (v18+); the
  // Buffer.from() wrap is REQUIRED for Buffer.concat to accept it on
  // the next line. The matching wrap in scripts/founder-bootstrap.js
  // is the byte-for-byte mirror — both CLIs MUST stay in lockstep so
  // a sig made by one verifies under the other. Pin:
  // tests/governance/founder-identity-roundtrip.test.js exercises
  // both code paths through the same derivation.
  const okm  = Buffer.from(crypto.hkdfSync('sha512', ikm, salt, info, HKDF_OUTPUT_LEN));
  const privDer = Buffer.concat([ED25519_PKCS8_PREFIX, okm]);
  const privKey = crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  const pubKey  = crypto.createPublicKey(privKey);
  return { privKey, pubKey };
}

// ── Args + wallet-rpc client (same shape as bootstrap) ──────────

// Accepts BOTH `--flag value` (two-arg) AND `--flag=value` (one-arg)
// forms. See scripts/founder-bootstrap.js::parseArgs for rationale.
function parseArgs(argv) {
  const out = {
    walletRpcUrl: 'http://127.0.0.1:27750',
    version: null,
    payloadFile: null,
    help: false,
  };
  const flagMap = {
    '--wallet-rpc-url': 'walletRpcUrl',
    '--version':        'version',
    '--payload-file':   'payloadFile',
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') { out.help = true; continue; }
    const eq = a.indexOf('=');
    if (eq > 0) {
      const key = a.slice(0, eq);
      if (flagMap[key]) { out[flagMap[key]] = a.slice(eq + 1); continue; }
      diagnostic('unknown arg: ' + key + ' (use --help)');
      process.exit(2);
    }
    if (flagMap[a] && argv[i + 1] !== undefined) {
      out[flagMap[a]] = argv[++i];
      continue;
    }
    diagnostic('unknown arg: ' + a + ' (use --help)');
    process.exit(2);
  }
  return out;
}

function diagnostic(msg) {
  process.stderr.write('[founder-sign-proposal] ' + msg + '\n');
}

// Refuse to talk to anything other than localhost. See
// scripts/founder-bootstrap.js::requireLoopbackUrl for the full
// rationale + accepted forms. THIS implementation MUST stay
// byte-equivalent — pinned by
// tests/static/founder-cli-loopback-guard.test.js.
function requireLoopbackUrl(rpcUrl) {
  let u;
  try { u = new URL(rpcUrl); }
  catch (e) { throw new Error('wallet-rpc URL is malformed: ' + e.message); }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host === '::1') return;
  if (/^127\.\d+\.\d+\.\d+$/.test(host))      return;
  if (/^::ffff:127\.\d+\.\d+\.\d+$/i.test(host)) return;
  const m = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (m) {
    const hi = parseInt(m[1], 16);
    const a = (hi >> 8) & 0xff;
    if (a === 127) return;
  }
  throw new Error('wallet-rpc URL must be loopback (127.0.0.1 / ::1 / localhost / ::ffff:127.x.x.x), got: '
    + host + ' — refusing to send spend_key query over a non-loopback transport');
}

function usage() {
  process.stderr.write(`
founder-sign-proposal.js — sign a CodeAmendment proposal with the
                           founder identity (locally, never via UI).

Usage:
  node scripts/founder-sign-proposal.js \\
    --wallet-rpc-url http://127.0.0.1:27750 \\
    --version v1 \\
    --payload-file /tmp/proposal.json

Where /tmp/proposal.json is the proposal payload EXPORTED FROM THE
WALLET WIZARD via "Save canonical payload for founder signing". The
file MUST be the pre-sign shape (no founderSig / creatorStealthSig
fields populated yet).

Output (STDOUT, single line):
  founder_sig: <128-hex-chars>

Paste the hex into the wizard's "Founder signature" field; the wizard
verifies it against the pinned pubkey before the Broadcast button is
enabled.
`);
}

function walletRpcQueryKey(rpcUrl, keyType, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const u    = new URL('/json_rpc', rpcUrl);
    const body = JSON.stringify({
      jsonrpc: '2.0', id: 'founder-sign', method: 'query_key',
      params: { key_type: keyType },
    });
    const req = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: timeoutMs,
    }, (res) => {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c) => {
        buf += c;
        if (buf.length > 64 * 1024) req.destroy(new Error('rpc body > 64 KB cap'));
      });
      res.on('end', () => {
        try {
          const j = JSON.parse(buf);
          if (j.error)                          return reject(new Error('rpc error: ' + (j.error.message || JSON.stringify(j.error))));
          if (!j.result || typeof j.result.key !== 'string') return reject(new Error('rpc returned no key field'));
          resolve(j.result.key);
        } catch (e) { reject(new Error('rpc body not JSON: ' + e.message)); }
      });
    });
    req.on('error',   reject);
    req.on('timeout', () => req.destroy(new Error('rpc timeout')));
    req.write(body); req.end();
  });
}

// ── Main ──────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);
  if (args.help)                            { usage(); process.exit(0); }
  if (!args.version || !args.payloadFile)   {
    diagnostic('ERROR: --version vN and --payload-file PATH are both required');
    usage(); process.exit(2);
  }

  // 1. Read + parse the payload file (must fit 32 KB cap)
  let payloadStr;
  try { payloadStr = fs.readFileSync(path.resolve(args.payloadFile), 'utf8'); }
  catch (e) { diagnostic('ERROR: cannot read payload file: ' + e.message); process.exit(3); }
  if (Buffer.byteLength(payloadStr, 'utf8') > 32 * 1024) {
    diagnostic('ERROR: payload file > 32 KB (cap is 32768 bytes)'); process.exit(3);
  }
  let payload;
  try { payload = JSON.parse(payloadStr); }
  catch (e) { diagnostic('ERROR: payload file is not valid JSON: ' + e.message); process.exit(3); }

  // 2. Pre-flight checks — the wallet should have stripped these
  //    fields already, but enforce here so we never accidentally
  //    sign a partially-signed payload (the canonicalizer strips
  //    them anyway, but a non-empty auth field in the input is a
  //    signal that the wallet pipeline upstream is broken).
  for (const f of AUTH_FIELDS_TO_STRIP) {
    if (payload[f] !== undefined && payload[f] !== null) {
      diagnostic('ERROR: payload[' + f + '] is non-null — wallet exported wrong shape');
      diagnostic('       (auth fields must be absent or null at founder-sign time)');
      process.exit(3);
    }
  }

  // 3. Re-derive the founder keypair from wallet-rpc
  try { requireLoopbackUrl(args.walletRpcUrl); }
  catch (e) { diagnostic('ERROR: ' + e.message); process.exit(2); }

  diagnostic('querying wallet-rpc at ' + args.walletRpcUrl + ' (wallet must be open)');
  let spendPriv;
  try { spendPriv = await walletRpcQueryKey(args.walletRpcUrl, 'spend_key'); }
  catch (e) { diagnostic('ERROR: ' + e.message); process.exit(3); }

  let kp;
  try { kp = deriveFounderKeypair(spendPriv, args.version); }
  catch (e) { diagnostic('ERROR: derivation failed: ' + e.message); process.exit(4); }

  // 4. Canonicalize + sign
  const canonical = canonicalizeForHash(payload);
  const sig       = crypto.sign(null, canonical, kp.privKey);

  // 5. Self-verify — never publish an unverifiable sig. Same defensive
  //    pattern as scripts/publish-peer-manifest.js (rule 44 — never
  //    silently fall back).
  const ok = crypto.verify(null, canonical, kp.pubKey, sig);
  if (!ok) {
    diagnostic('ERROR: self-verify failed — refusing to publish sig');
    process.exit(5);
  }

  // 6. STDOUT — single line, machine-parseable.
  process.stdout.write('founder_sig: ' + sig.toString('hex') + '\n');

  diagnostic('SUCCESS. Paste the line above into the wizard\'s "Founder signature" field.');
  diagnostic('The wizard will verify it against the pinned FOUNDER_PUBKEYS[' + args.version + '] before enabling Broadcast.');
}

main().catch((e) => {
  diagnostic('FATAL: ' + (e && e.message ? e.message : String(e)));
  process.exit(1);
});
