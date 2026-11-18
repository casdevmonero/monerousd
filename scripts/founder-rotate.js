#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/* scripts/founder-rotate.js
 *
 * CodeAmendment v1 (CA-10) — founder pubkey rotation ceremony.
 *
 * Adds a new vN pubkey to the FOUNDER_PUBKEYS list across BOTH the
 * wallet's CJS file (`build-1261/lib/founder-pubkeys.js`) AND the
 * backend's JSON mirror (`ion-monerousd-org/backend/governance/founder-pubkeys.json`)
 * in a single atomic ceremony. Bumps CURRENT_VERSION to vN.
 *
 * USAGE
 * ─────
 *   # Bootstrap derives the new pubkey from the founder's wallet:
 *   PUB=$(node scripts/founder-bootstrap.js \
 *           --wallet-keys-path ~/.monerousd/wallets/founder/keys \
 *           --password-from-fd 3 3<<<"$WALLET_PASSWORD" \
 *           --version v2 | sed -n 's/^founder_pub_v2: //p')
 *
 *   # Append-and-bump:
 *   node scripts/founder-rotate.js --version v2 --pubkey "$PUB"
 *
 *   # Verify both files are now in sync:
 *   node --test \
 *     ion-monerousd-org/tests/static/founder-pubkeys-backend-wallet-parity.test.js \
 *     ion-monerousd-org/tests/static/founder-pubkeys-consistency.test.js
 *
 * SECURITY MODEL
 * ──────────────
 *
 * 1. NO new pubkey is INVENTED here — the operator provides it
 *    via --pubkey, derived offline via founder-bootstrap.js. The
 *    rotation CLI is pure file editing; it never touches the wallet
 *    keys.
 *
 * 2. Both files are validated before write:
 *      • --pubkey must be 64-char lowercase hex
 *      • --version must match /^v\d+$/ AND be greater than every
 *        existing version in the array
 *      • The pubkey must NOT already exist in either file
 *
 * 3. Both files are written ATOMICALLY (tmp + rename). If the wallet
 *    file write succeeds but the backend file write fails, the
 *    operator MUST re-run with --backend-only to catch up the
 *    backend (the script detects + reports the inconsistency).
 *
 * 4. Rotation is APPEND-ONLY — older entries STAY so historical
 *    proposals retain the silver ☆ FOUNDER-vN badge in the
 *    explorer's audit trail. No --remove flag.
 *
 * 5. After write, the script runs the parity test suite (if
 *    --skip-test is not passed) and fails loudly on mismatch.
 */

import fs           from 'node:fs';
import path         from 'node:path';
import process      from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const REPO_ROOT          = path.resolve(__dirname, '..');
const WALLET_CJS_PATH    = path.resolve(REPO_ROOT, 'build-1261', 'lib', 'founder-pubkeys.js');
const BACKEND_JSON_PATH  = path.resolve(REPO_ROOT, 'ion-monerousd-org', 'backend', 'governance', 'founder-pubkeys.json');

// ── Args ─────────────────────────────────────────────────────────

function parseArgs(argv) {
  const out = { version: null, pubkey: null, skipTest: false, backendOnly: false, walletOnly: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--version')     out.version = argv[++i];
    else if (a === '--pubkey') out.pubkey  = argv[++i];
    else if (a === '--skip-test')   out.skipTest = true;
    else if (a === '--backend-only') out.backendOnly = true;
    else if (a === '--wallet-only')  out.walletOnly  = true;
    else if (a === '--help' || a === '-h') { printUsage(); process.exit(0); }
    else fail(`unknown arg: ${a}`);
  }
  if (!out.version) fail('--version required (e.g. --version v2)');
  if (!out.pubkey)  fail('--pubkey required (64-char lowercase hex from founder-bootstrap.js)');
  if (!/^v\d+$/.test(out.version)) fail(`--version must match /^v\\d+$/, got "${out.version}"`);
  if (!/^[0-9a-f]{64}$/.test(out.pubkey)) fail(`--pubkey must be 64-char lowercase hex, got "${out.pubkey}"`);
  if (out.backendOnly && out.walletOnly) fail('--backend-only and --wallet-only are mutually exclusive');
  return out;
}

function fail(msg) { console.error(`[founder-rotate] FATAL: ${msg}`); process.exit(1); }

function printUsage() {
  console.error([
    'Usage: node scripts/founder-rotate.js --version vN --pubkey <64-hex> [--skip-test] [--backend-only|--wallet-only]',
    '',
    'Appends a new founder pubkey entry to BOTH:',
    `  ${WALLET_CJS_PATH}`,
    `  ${BACKEND_JSON_PATH}`,
    'AND bumps CURRENT_VERSION to vN.',
    '',
    'Generate the pubkey first via:',
    '  node scripts/founder-bootstrap.js --wallet-keys-path ... --version vN',
  ].join('\n'));
}

// ── File readers ─────────────────────────────────────────────────

function readBackendJson() {
  try {
    return JSON.parse(fs.readFileSync(BACKEND_JSON_PATH, 'utf8'));
  } catch (e) {
    fail(`cannot parse backend JSON: ${e.message}`);
  }
}

function readWalletCjs() {
  // Parse the CJS file. The format is fixed:
  //   const FOUNDER_PUBKEYS = Object.freeze([
  //     { version: 'vN', pubkey: '<64-hex>' },
  //     ...
  //   ]);
  //   const CURRENT_VERSION = 'vN';
  const src = fs.readFileSync(WALLET_CJS_PATH, 'utf8');
  const entries = [];
  const entryRe = /\{\s*version:\s*'(v\d+)'\s*,\s*pubkey:\s*'([0-9a-f]{64})'\s*\}/g;
  let m;
  while ((m = entryRe.exec(src)) !== null) {
    entries.push({ version: m[1], pubkey: m[2] });
  }
  const verMatch = src.match(/const\s+CURRENT_VERSION\s*=\s*'(v\d+)'/);
  return {
    FOUNDER_PUBKEYS: entries,
    CURRENT_VERSION: verMatch ? verMatch[1] : null,
    rawSrc: src,
  };
}

// ── Validation ───────────────────────────────────────────────────

function validateBumpAllowed({ existing, version, pubkey }) {
  for (const entry of existing.FOUNDER_PUBKEYS) {
    if (entry.version === version) {
      fail(`version ${version} already exists in file with pubkey ${entry.pubkey} — rotation must use a NEW version`);
    }
    if (entry.pubkey === pubkey) {
      fail(`pubkey ${pubkey} is already pinned under version ${entry.version} — refusing to add duplicate`);
    }
  }
  // Version must be strictly greater than every existing version.
  const newN = Number(version.slice(1));
  for (const entry of existing.FOUNDER_PUBKEYS) {
    const existN = Number(entry.version.slice(1));
    if (newN <= existN) {
      fail(`new version ${version} is not greater than existing ${entry.version} — append-only rotation`);
    }
  }
}

// ── Writers (atomic via tmp + rename) ─────────────────────────────

function atomicWrite(absPath, content) {
  const tmp = absPath + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, content);
  fs.renameSync(tmp, absPath);
}

function writeBackendJson({ existing, version, pubkey }) {
  const next = { ...existing };
  next.FOUNDER_PUBKEYS = [...existing.FOUNDER_PUBKEYS, { version, pubkey }];
  next.CURRENT_VERSION = version;
  atomicWrite(BACKEND_JSON_PATH, JSON.stringify(next, null, 2) + '\n');
  console.log(`[founder-rotate] wrote backend JSON: ${BACKEND_JSON_PATH}`);
}

function writeWalletCjs({ existing, version, pubkey }) {
  // Re-render the array entirely so formatting stays consistent.
  // Keep the file's header comment block; replace only the
  // FOUNDER_PUBKEYS array body + the CURRENT_VERSION line.
  const next = [...existing.FOUNDER_PUBKEYS, { version, pubkey }];
  const arrayBody = next
    .map((e) => `  { version: '${e.version}', pubkey: '${e.pubkey}' },`)
    .join('\n');

  let src = existing.rawSrc;
  // Replace the FOUNDER_PUBKEYS array literal.
  src = src.replace(
    /const\s+FOUNDER_PUBKEYS\s*=\s*Object\.freeze\(\[[\s\S]*?\]\);/m,
    `const FOUNDER_PUBKEYS = Object.freeze([\n${arrayBody}\n]);`
  );
  // Replace CURRENT_VERSION.
  src = src.replace(
    /const\s+CURRENT_VERSION\s*=\s*'v\d+';/,
    `const CURRENT_VERSION = '${version}';`
  );
  atomicWrite(WALLET_CJS_PATH, src);
  console.log(`[founder-rotate] wrote wallet CJS: ${WALLET_CJS_PATH}`);
}

// ── Post-write verification ──────────────────────────────────────

function runParityTests() {
  const result = spawnSync(
    'node',
    ['--test',
     path.resolve(REPO_ROOT, 'ion-monerousd-org', 'tests', 'static', 'founder-pubkeys-backend-wallet-parity.test.js'),
     path.resolve(REPO_ROOT, 'ion-monerousd-org', 'tests', 'static', 'founder-pubkeys-consistency.test.js')],
    { stdio: 'inherit', cwd: path.resolve(REPO_ROOT, 'ion-monerousd-org') }
  );
  if (result.status !== 0) {
    fail('parity tests failed after rotation — files are now INCONSISTENT. Re-run with --backend-only or --wallet-only after manual inspection.');
  }
  console.log('[founder-rotate] parity tests passed.');
}

// ── Main ─────────────────────────────────────────────────────────

const args = parseArgs(process.argv);

const backendBefore = readBackendJson();
const walletBefore  = readWalletCjs();

// Cross-file pre-check — refuse if the two were already inconsistent.
if (!args.backendOnly && !args.walletOnly) {
  if (backendBefore.CURRENT_VERSION !== walletBefore.CURRENT_VERSION) {
    fail(`PRE-CHECK FAIL: backend CURRENT_VERSION=${backendBefore.CURRENT_VERSION} ` +
         `but wallet CURRENT_VERSION=${walletBefore.CURRENT_VERSION}. ` +
         'Reconcile before rotating.');
  }
  if (backendBefore.FOUNDER_PUBKEYS.length !== walletBefore.FOUNDER_PUBKEYS.length) {
    fail(`PRE-CHECK FAIL: backend has ${backendBefore.FOUNDER_PUBKEYS.length} pubkeys ` +
         `but wallet has ${walletBefore.FOUNDER_PUBKEYS.length}. Reconcile before rotating.`);
  }
}

// Validate the bump against whichever file we're editing.
const validateAgainst = args.walletOnly ? walletBefore : backendBefore;
validateBumpAllowed({
  existing: validateAgainst,
  version:  args.version,
  pubkey:   args.pubkey,
});

// Atomic writes.
if (!args.backendOnly) {
  writeWalletCjs({ existing: walletBefore, version: args.version, pubkey: args.pubkey });
}
if (!args.walletOnly) {
  writeBackendJson({ existing: backendBefore, version: args.version, pubkey: args.pubkey });
}

console.log(
  `[founder-rotate] rotation v${args.version.slice(1)} complete. ` +
  `New pubkey ${args.pubkey.slice(0, 12)}… is now pinned.`
);

if (!args.skipTest) {
  runParityTests();
}

console.log('[founder-rotate] DONE. Ship the next wallet release with the updated files.');
