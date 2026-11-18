#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/* scripts/founder-bootstrap.js
 *
 * One-shot CLI that derives the founder identity pubkey from the
 * founder's wallet spend key via HKDF-SHA512. Outputs `founder_pub_<vN>:
 * <64-hex>` to STDOUT and NOTHING else. This pubkey gets pinned into
 * build-1261/lib/founder-pubkeys.js so the wallet's renderer can verify
 * founder-tagged CodeAmendment proposals.
 *
 * CRITICAL — security model (spec §12):
 *
 *   1. NO wallet UI for this. Anyone running the wallet binary on
 *      their own machine could call a UI-exposed version and derive
 *      THEIR OWN "founder pubkey" — which would be perfectly valid
 *      ed25519 but not the one pinned in the wallet binary, so the
 *      gold ★ FOUNDER tag would never appear. Worse, a sloppy UI
 *      could leak the wallet address (forbidden by spec §12).
 *
 *   2. CLI runs on the founder's secure machine, reads the wallet
 *      keys file directly (NEVER over the network), derives the
 *      pubkey via HKDF, prints to stdout, exits. No log files, no
 *      temp files, no env-var output.
 *
 *   3. The wallet address is NEVER printed. Only the HKDF-derived
 *      pubkey (which is one-way unlinkable to the address).
 *
 *   4. The wallet's spend_priv is loaded only via the
 *      MoneroUSD wallet-rpc `query_key` method — meaning the
 *      bootstrap requires the wallet-rpc to be running with the
 *      target wallet OPEN. This avoids re-implementing seed →
 *      spend-key derivation in JS (which would be a rich
 *      attack surface).
 *
 * Usage:
 *   node scripts/founder-bootstrap.js \
 *     --wallet-rpc-url http://127.0.0.1:27750 \
 *     --version v1
 *
 * Output (single line, STDOUT only):
 *   founder_pub_v1: <64-hex-chars>
 *
 * The founder copies this hex into build-1261/lib/founder-pubkeys.js's
 * FOUNDER_PUBKEYS array as `{ version: 'v1', pubkey: '<64-hex>' }`,
 * bumps CURRENT_VERSION to 'v1', and ships a wallet release.
 *
 * Rotation: re-run with `--version v2` (or v3, etc.) → different
 * pubkey. Append to FOUNDER_PUBKEYS (don't replace), bump
 * CURRENT_VERSION. Historical entries keep the silver ☆ FOUNDER-vN
 * tag in the explorer's audit trail.
 *
 * Hard rules enforced:
 *   - STDOUT contains EXACTLY one line: `founder_pub_<vN>: <64-hex>`
 *   - STDERR may contain progress / errors (so the operator sees
 *     what's happening) but never the spend_priv or wallet address
 *   - Exit code 0 = success; non-zero = anything else
 *   - No file I/O other than reading argv + writing stdout
 *   - No network I/O other than the localhost wallet-rpc call
 */

'use strict';

const crypto = require('node:crypto');
const http   = require('node:http');
const { URL } = require('node:url');

// ── Arg parsing — tiny, no deps ───────────────────────────────────

// Accepts BOTH `--flag value` (two-arg) AND `--flag=value` (one-arg)
// forms. Operators copy-paste from shell histories where either form
// is conventional; rejecting one is a frustrating UX bug.
function parseArgs(argv) {
  const out = {
    walletRpcUrl: 'http://127.0.0.1:27750',
    version: null,
    help: false,
  };
  const flagMap = {
    '--wallet-rpc-url': 'walletRpcUrl',
    '--version':        'version',
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') { out.help = true; continue; }
    // `--flag=value` one-arg form.
    const eq = a.indexOf('=');
    if (eq > 0) {
      const key = a.slice(0, eq);
      if (flagMap[key]) { out[flagMap[key]] = a.slice(eq + 1); continue; }
      diagnostic('unknown arg: ' + key + ' (use --help)');
      process.exit(2);
    }
    // `--flag value` two-arg form.
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
  process.stderr.write('[founder-bootstrap] ' + msg + '\n');
}

// Refuse to talk to anything other than localhost. A spend_key query
// over the network is the single worst leak the CLI could enable, so
// we hardcode-reject non-loopback URLs even if the operator typed one
// by accident.
//
// Accepted loopback forms:
//   - localhost                  (DNS label; URL.hostname returns 'localhost'
//                                 verbatim, no resolution)
//   - 127.0.0.0/8                (any IPv4 in the loopback block)
//   - ::1                        (IPv6 loopback)
//   - ::ffff:127.x.x.x           (IPv6-mapped IPv4 — Node emits this form
//                                 when wallet-rpc binds dual-stack [::]
//                                 and the operator hits it via the v6
//                                 socket; legitimate loopback)
//
// We do NOT resolve DNS on `localhost`; some operators alias `localhost`
// to a non-loopback address in /etc/hosts. The risk of accepting a
// non-loopback `localhost` is bounded — DNS hijacking on the founder's
// own machine is already game over for any wallet-rpc connection.
function requireLoopbackUrl(rpcUrl) {
  let u;
  try { u = new URL(rpcUrl); }
  catch (e) {
    throw new Error('wallet-rpc URL is malformed: ' + e.message);
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');   // strip IPv6 brackets
  if (host === 'localhost' || host === '::1') return;
  if (/^127\.\d+\.\d+\.\d+$/.test(host))      return;
  if (/^::ffff:127\.\d+\.\d+\.\d+$/i.test(host)) return;
  // Also accept the all-hex form Node sometimes emits (`::ffff:7f00:1`
  // for 127.0.0.1). Decode the trailing two u16s and check it's 127.x.x.x.
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
founder-bootstrap.js — derive the founder identity pubkey for the
                       MoneroUSD CodeAmendment governance system.

Usage:
  node scripts/founder-bootstrap.js \\
    --wallet-rpc-url http://127.0.0.1:27750 \\
    --version v1

Prerequisites:
  - MoneroUSD wallet-rpc running locally
  - The target wallet OPEN in that wallet-rpc (the wallet whose
    seed identifies the founder)

Output (STDOUT, single line):
  founder_pub_v1: <64-hex-chars>

Paste the hex into build-1261/lib/founder-pubkeys.js's FOUNDER_PUBKEYS
array and ship a wallet release. See docs/CODE-AMENDMENT-V1.md §12.
`);
}

// ── HKDF-SHA512 domain separation ─────────────────────────────────

const HKDF_DOMAIN_PREFIX = 'monerousd-founder-tag-';
const HKDF_OUTPUT_LEN    = 32;   // 32 bytes = ed25519 seed length

// Pubkey derivation:
//   1. Pull spend_priv (64-byte hex) from wallet-rpc query_key
//   2. HKDF-SHA512 with info = `monerousd-founder-tag-v<N>` to get
//      a 32-byte ed25519 SEED (deterministic per spend_priv + version)
//   3. Construct an ed25519 keypair from the seed — the public half
//      is the founder pubkey we ship
//
// Why HKDF + a per-version domain separator:
//   - HKDF is a standard, audit-friendly KDF; no novel crypto
//   - The version tag ensures rotation produces a DIFFERENT pubkey
//     even from the SAME spend_priv
//   - The pubkey is one-way: knowing it doesn't reveal spend_priv
//     OR the wallet address
// Fixed 16-byte PKCS#8 prefix for ed25519 — the ed25519 private key
// format is `prefix || 32-byte raw seed`. We construct the wrapped DER
// directly from the HKDF output so we never have to round-trip through
// generateKeyPair (which doesn't accept a seed-from-bytes API in
// Node's stdlib crypto).
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

// Fixed 12-byte SPKI prefix for an ed25519 pubkey (RFC 8410). Used to
// reconstruct a verifiable public key object from the 32-byte raw
// pubkey output by deriveFounderPubkey. Mirrors the same constant in
// founder-sign-proposal.js and lib/founder-pubkeys.js verifier paths.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function deriveFounderPubkey(spendPrivHex, version) {
  if (!/^[0-9a-f]{64}$/.test(spendPrivHex)) {
    throw new Error('spend_priv from wallet-rpc is not 64-char hex (got length ' + spendPrivHex.length + ')');
  }
  if (!/^v[1-9][0-9]*$/.test(version)) {
    throw new Error('version must be vN where N >= 1 (got: ' + version + ')');
  }
  const ikm  = Buffer.from(spendPrivHex, 'hex');
  const salt = Buffer.alloc(0);                                  // HKDF empty-salt mode
  const info = Buffer.from(HKDF_DOMAIN_PREFIX + version, 'utf8');
  const okm  = Buffer.from(crypto.hkdfSync('sha512', ikm, salt, info, HKDF_OUTPUT_LEN));
  const privDer = Buffer.concat([ED25519_PKCS8_PREFIX, okm]);
  const privKey = crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  const pubKey  = crypto.createPublicKey(privKey);
  const pubDer  = pubKey.export({ type: 'spki', format: 'der' });
  // SPKI DER for an ed25519 pubkey is a fixed 12-byte preamble + the
  // 32 pubkey bytes. We slice off the preamble. (Robust because
  // ed25519 SPKI shape is RFC 8410 frozen.)
  const pubBytes = pubDer.slice(-32);

  // SELF-VERIFY (rule 49 — never silently fall back). Sign a fixed
  // canonical test string with the private half, reconstruct the
  // public half from the printed hex via the same SPKI assembly the
  // wallet's verifier will use, verify the sig. Refuse to return if
  // verify fails — otherwise we'd ship a bogus pubkey that no future
  // proposal sig could ever match, and the founder feature would be
  // silently dormant forever.
  const SELF_TEST_MSG = Buffer.from('monerousd-founder-bootstrap-self-test-v1', 'utf8');
  const sig = crypto.sign(null, SELF_TEST_MSG, privKey);
  const verifierPubKey = crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, pubBytes]),
    format: 'der',
    type:   'spki',
  });
  const ok = crypto.verify(null, SELF_TEST_MSG, verifierPubKey, sig);
  if (!ok) {
    throw new Error('FOUNDER_BOOTSTRAP_SELF_VERIFY_FAILED — '
      + 'derived keypair did not pass round-trip sign+verify. This is a '
      + 'crypto-environment bug (Node/OpenSSL version mismatch?); refusing '
      + 'to ship a pubkey that no future signature could match.');
  }

  // Caller MUST NOT log privDer / okm / privKey — they are not
  // returned and fall out of scope at function exit.
  return pubBytes.toString('hex');
}

// ── wallet-rpc query_key client (POST /json_rpc) ─────────────────

function walletRpcQueryKey(rpcUrl, keyType, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const u    = new URL('/json_rpc', rpcUrl);
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: 'founder-bootstrap',
      method: 'query_key',
      params: { key_type: keyType },
    });
    const req = http.request({
      hostname: u.hostname,
      port:     u.port,
      path:     u.pathname,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout:  timeoutMs,
    }, (res) => {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c) => {
        buf += c;
        if (buf.length > 64 * 1024) {
          req.destroy(new Error('wallet-rpc response body > 64 KB cap'));
        }
      });
      res.on('end', () => {
        try {
          const j = JSON.parse(buf);
          if (j.error) {
            return reject(new Error('wallet-rpc error: ' + (j.error.message || JSON.stringify(j.error))));
          }
          if (!j.result || typeof j.result.key !== 'string') {
            return reject(new Error('wallet-rpc returned no key field'));
          }
          resolve(j.result.key);
        } catch (e) {
          reject(new Error('wallet-rpc response not JSON: ' + e.message));
        }
      });
    });
    req.on('error',   reject);
    req.on('timeout', () => req.destroy(new Error('wallet-rpc timeout after ' + timeoutMs + ' ms')));
    req.write(body);
    req.end();
  });
}

// ── Main ──────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);
  if (args.help)          { usage(); process.exit(0); }
  if (!args.version)      {
    diagnostic('ERROR: --version vN is required (e.g. --version v1)');
    usage();
    process.exit(2);
  }
  if (!/^v[1-9][0-9]*$/.test(args.version)) {
    diagnostic('ERROR: --version must be vN where N >= 1 (got: ' + args.version + ')');
    process.exit(2);
  }

  try { requireLoopbackUrl(args.walletRpcUrl); }
  catch (e) {
    diagnostic('ERROR: ' + e.message);
    process.exit(2);
  }

  diagnostic('querying wallet-rpc at ' + args.walletRpcUrl + ' (wallet must be open)');

  let spendPriv;
  try {
    spendPriv = await walletRpcQueryKey(args.walletRpcUrl, 'spend_key');
  } catch (e) {
    diagnostic('ERROR: ' + e.message);
    diagnostic('Hint: start wallet-rpc and open the founder wallet first.');
    process.exit(3);
  }

  if (!spendPriv || typeof spendPriv !== 'string' || spendPriv.length === 0) {
    diagnostic('ERROR: wallet-rpc returned empty spend_key');
    process.exit(3);
  }

  let pubHex;
  try {
    pubHex = deriveFounderPubkey(spendPriv, args.version);
  } catch (e) {
    diagnostic('ERROR: derivation failed: ' + e.message);
    process.exit(4);
  }

  // STDOUT — single line, machine-parseable.
  process.stdout.write('founder_pub_' + args.version + ': ' + pubHex + '\n');

  diagnostic('SUCCESS. Paste the line above into build-1261/lib/founder-pubkeys.js:');
  diagnostic('  - Append to FOUNDER_PUBKEYS: { version: \'' + args.version + '\', pubkey: \'' + pubHex + '\' }');
  diagnostic('  - Set CURRENT_VERSION = \'' + args.version + '\'');
  diagnostic('  - Ship a wallet release.');
}

main().catch((e) => {
  diagnostic('FATAL: ' + (e && e.message ? e.message : String(e)));
  process.exit(1);
});
