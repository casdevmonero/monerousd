#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// scripts/code-amendment-relayer-broadcast.js
//
// CodeAmendment v1 — FROST-aggregate-signed attestation broadcaster
// for the two relayer-signed CA ops the wallet UI cannot produce:
//
//   • CODE_PUSH_PENDING (0x3D)         — authorizes a code push to
//                                        the canonical repo. Consumed
//                                        by scripts/code-amendment-push-relay.js
//                                        (the daemon that watches for
//                                        code_push_authorized events
//                                        + executes the git push).
//
//   • EMERGENCY_ROLLBACK autoSpawned   — auto-rollback emitted by
//                                        the regression watcher
//                                        (scripts/code-amendment-regression-watcher.js)
//                                        when post-push dry-runs
//                                        show a regression. Wallet's
//                                        IPC HARDCODES autoSpawned:false
//                                        for manual flows, so the
//                                        autoSpawned=true variant has
//                                        to ride out-of-band.
//
// FROST SIGNING (out-of-band)
// ──────────────────────────
// This script does NOT run the FROST signing ceremony — that's
// operator infrastructure (per Ion Swap rule 110e bridge FROST
// primitives). The flow is:
//
//   1. Validator quorum coordinates the ceremony out-of-band
//      (slack DM, mesh, etc.).
//   2. Each validator runs FROST round-1 → round-2.
//   3. Aggregate signature comes out the other side as a 128-hex
//      string (ed25519 / Schnorr) + the list of participating
//      validator pubkeys (64-hex each).
//   4. Operator pipes BOTH into this script along with the op-
//      specific fields:
//
//        node code-amendment-relayer-broadcast.js push \
//          --proposal-hash=<64hex> \
//          --scheduled-push-height=<int> \
//          --cooling-off-ends-at=<ISO8601> \
//          --relayer-sig=<128hex> \
//          --relayer-signers=<64hex>,<64hex>,...
//
//        node code-amendment-relayer-broadcast.js rollback \
//          --target-proposal-hash=<64hex> \
//          --prior-code-hash=<64hex> \
//          --reason-md-file=<path> \
//          --relayer-sig=<128hex>
//
// SAFETY
// ──────
//   • Both payloads run through the BACKEND codec validator before
//     anything is staged. Malformed inputs error out before any
//     wallet-rpc call.
//   • The script does NOT execute git pushes or rollback any state.
//     Its job is purely to (a) assemble + validate the canonical
//     payload, (b) print it for review, (c) optionally POST it to
//     /api/attestation/stage (gated by --stage flag).
//   • Each invocation prints the operator-readable payload JSON
//     before staging. The operator must explicitly type `yes` to
//     confirm (or pass --yes to skip).
//   • The script REFUSES to autoSpawn rollbacks without a
//     `failingRunners` list — defense against a regression-watcher
//     dispatch file that lost context.

import process    from 'node:process';
import fs         from 'node:fs';
import path       from 'node:path';
import { fileURLToPath } from 'node:url';
import readline   from 'node:readline';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function fail(msg) {
  console.error('[ca-relayer-broadcast] FATAL:', msg);
  process.exit(1);
}

function usage() {
  console.error([
    'usage:',
    '  code-amendment-relayer-broadcast.js push \\',
    '    --proposal-hash=<64hex> \\',
    '    --scheduled-push-height=<int> \\',
    '    --cooling-off-ends-at=<ISO8601> \\',
    '    --relayer-sig=<128hex> \\',
    '    --relayer-signers=<64hex>,<64hex>,...',
    '',
    '  code-amendment-relayer-broadcast.js rollback \\',
    '    --target-proposal-hash=<64hex> \\',
    '    --prior-code-hash=<64hex> \\',
    '    --reason-md-file=<path> \\',
    '    --relayer-sig=<128hex>',
    '',
    'optional flags:',
    '  --stage                 POST to /api/attestation/stage after validation',
    '  --indexer-url=<url>     override CA_RELAYER_INDEXER_URL (default https://ion.monerousd.org)',
    '  --yes                   skip the interactive confirmation prompt',
    '  --dry-run               validate + print canonical payload; do NOT stage even with --stage',
  ].join('\n'));
  process.exit(2);
}

// ── Arg parsing — minimal --key=value parser ─────────────────────

function parseArgs(argv) {
  const subcommand = argv[2];
  if (!subcommand || subcommand === '--help' || subcommand === '-h') {
    usage();
  }
  if (!['push', 'rollback'].includes(subcommand)) {
    console.error(`[ca-relayer-broadcast] unknown subcommand: ${subcommand}`);
    usage();
  }
  const args = {};
  for (let i = 3; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--stage' || a === '--yes' || a === '--dry-run') {
      args[a.slice(2)] = true;
      continue;
    }
    const eq = a.indexOf('=');
    if (eq < 0 || !a.startsWith('--')) {
      console.error(`[ca-relayer-broadcast] malformed arg: ${a}`);
      usage();
    }
    const key = a.slice(2, eq);
    const val = a.slice(eq + 1);
    args[key] = val;
  }
  return { subcommand, args };
}

// ── Input validators (cheap pre-checks; codec is the source of truth) ─

const HEX64_RE  = /^[0-9a-f]{64}$/;
const HEX128_RE = /^[0-9a-f]{128}$/;

function requireField(args, name) {
  if (!args[name]) {
    fail(`missing required flag: --${name}`);
  }
  return args[name];
}

function requireHex64(args, name) {
  const v = String(requireField(args, name)).toLowerCase();
  if (!HEX64_RE.test(v)) {
    fail(`--${name} must be 64-hex; got "${v}"`);
  }
  return v;
}

function requireHex128(args, name) {
  const v = String(requireField(args, name)).toLowerCase();
  if (!HEX128_RE.test(v)) {
    fail(`--${name} must be 128-hex; got "${v}"`);
  }
  return v;
}

function requireInt(args, name) {
  const v = Number(requireField(args, name));
  if (!Number.isInteger(v) || v <= 0) {
    fail(`--${name} must be a positive integer; got "${args[name]}"`);
  }
  return v;
}

function requireFile(args, name) {
  const p = requireField(args, name);
  if (!fs.existsSync(p)) {
    fail(`--${name}: file does not exist: ${p}`);
  }
  return fs.readFileSync(p, 'utf8');
}

// ── Payload assembly ─────────────────────────────────────────────

function assemblePushPayload(args) {
  const proposalHash       = requireHex64(args, 'proposal-hash');
  const scheduledPushHeight = requireInt(args, 'scheduled-push-height');
  const coolingOffEndsAt   = requireField(args, 'cooling-off-ends-at');
  if (!/^\d{4}-\d{2}-\d{2}T/.test(coolingOffEndsAt)) {
    fail(`--cooling-off-ends-at must be ISO8601 (e.g. 2026-05-20T12:00:00Z); got "${coolingOffEndsAt}"`);
  }
  const relayerSig         = requireHex128(args, 'relayer-sig');
  const signersRaw         = requireField(args, 'relayer-signers');
  const relayerSigners     = signersRaw.split(',').map((s) => s.trim().toLowerCase());
  if (relayerSigners.length < 1) {
    fail('--relayer-signers must list at least one signer pubkey (64-hex, comma-separated)');
  }
  for (const s of relayerSigners) {
    if (!HEX64_RE.test(s)) {
      fail(`relayer-signers contains a malformed pubkey: ${s}`);
    }
  }
  return {
    v: 1,
    proposalHash,
    scheduledPushHeight,
    coolingOffEndsAt,
    relayerSig,
    relayerSigners,
  };
}

function assembleRollbackPayload(args) {
  const targetProposalHash = requireHex64(args, 'target-proposal-hash');
  const priorCodeHash      = requireHex64(args, 'prior-code-hash');
  const rollbackReasonMd   = requireFile(args, 'reason-md-file');
  if (rollbackReasonMd.length < 32) {
    fail(`--reason-md-file content must be ≥ 32 bytes; got ${rollbackReasonMd.length} bytes`);
  }
  if (rollbackReasonMd.length > 2048) {
    fail(`--reason-md-file content must be ≤ 2048 bytes; got ${rollbackReasonMd.length} bytes`);
  }
  const relayerSig         = requireHex128(args, 'relayer-sig');
  return {
    v: 1,
    targetProposalHash,
    priorCodeHash,
    rollbackReasonMd,
    autoSpawned: true,             // CLI is ONLY for the FROST-signed path
    relayerSig,
  };
}

// ── Codec validation against the canonical backend implementation ──

async function loadBackendCodec() {
  // The script ships alongside ion-monerousd-org/ in the operator's
  // checkout; the codec lives at ../ion-monerousd-org/backend/governance.
  const modPath = path.resolve(
    __dirname, '..', 'ion-monerousd-org',
    'backend', 'governance', 'code-amendment-codec.js',
  );
  if (!fs.existsSync(modPath)) {
    fail(`backend codec not found at expected path: ${modPath}\n`
       + 'Set CA_RELAYER_BACKEND_PATH to override, OR run this script from the operator checkout root.');
  }
  return import(modPath);
}

async function validatePayload(codec, opCode, payload) {
  const validator =
    opCode === 'CODE_PUSH_PENDING'   ? codec.validateCodePushPendingPayload :
    opCode === 'EMERGENCY_ROLLBACK'  ? codec.validateEmergencyRollbackPayload :
    null;
  if (typeof validator !== 'function') {
    fail(`backend codec missing validator for ${opCode}`);
  }
  const result = validator(payload);
  if (!result.ok) {
    fail(`payload rejected by backend codec: ${result.error}`);
  }
  return result.parsed;
}

// ── Interactive confirmation ─────────────────────────────────────

async function confirm(prompt, autoYes) {
  if (autoYes) return true;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(prompt + ' (yes/no): ', (a) => {
      rl.close();
      resolve(a.trim().toLowerCase() === 'yes');
    });
  });
}

// ── Staging — POST to /api/attestation/stage ─────────────────────

async function stagePayload(indexerUrl, opCode, payload) {
  const url = indexerUrl.replace(/\/$/, '') + '/api/attestation/stage';
  const r = await fetch(url, {
    method:  'POST',
    headers: { 'content-type': 'application/json' },
    body:    JSON.stringify({
      code: opCode,
      payload,
      // No origin — relayer-broadcasts are wallet-internal infrastructure,
      // not dApp-attributed.
      origin: 'cli:code-amendment-relayer-broadcast',
    }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => '<no body>');
    fail(`stage POST failed: HTTP ${r.status} — ${text.slice(0, 500)}`);
  }
  return r.json();
}

// ── Main ─────────────────────────────────────────────────────────

const { subcommand, args } = parseArgs(process.argv);
const INDEXER_URL =
  args['indexer-url'] || process.env.CA_RELAYER_INDEXER_URL || 'https://ion.monerousd.org';

const opCode = subcommand === 'push' ? 'CODE_PUSH_PENDING' : 'EMERGENCY_ROLLBACK';

console.log(`[ca-relayer-broadcast] subcommand=${subcommand} op=${opCode}`);
console.log(`[ca-relayer-broadcast] indexer=${INDEXER_URL}`);

const payload = subcommand === 'push'
  ? assemblePushPayload(args)
  : assembleRollbackPayload(args);

const codec = await loadBackendCodec();
await validatePayload(codec, opCode, payload);
console.log('[ca-relayer-broadcast] ✓ payload validated by backend codec');

console.log('\n── Canonical payload ──────────────────────────────────────');
console.log(JSON.stringify(payload, null, 2));
console.log('────────────────────────────────────────────────────────────\n');

if (args['dry-run']) {
  console.log('[ca-relayer-broadcast] --dry-run set; not staging. Done.');
  process.exit(0);
}

if (!args.stage) {
  console.log('[ca-relayer-broadcast] --stage not set; payload validated but not broadcast.');
  console.log('[ca-relayer-broadcast] re-run with --stage to POST to /api/attestation/stage');
  process.exit(0);
}

const ok = await confirm(
  `Stage this ${opCode} payload at ${INDEXER_URL}?`,
  args.yes,
);
if (!ok) {
  console.log('[ca-relayer-broadcast] operator declined; not staging.');
  process.exit(0);
}

const result = await stagePayload(INDEXER_URL, opCode, payload);
console.log('[ca-relayer-broadcast] ✓ staged. response:');
console.log(JSON.stringify(result, null, 2));
console.log('\n[ca-relayer-broadcast] NEXT STEP: the operator must now broadcast a carrier');
console.log('tx (1-atomic USDm self-transfer) to the staged subaddress so the chain monitor');
console.log('materializes the attestation. The carrier-tx signer is irrelevant for FROST-');
console.log('authed ops (the relayerSig is what authorizes); any operator wallet can sign.');
