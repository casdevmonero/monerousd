#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// scripts/code-amendment-regression-watcher.js
//
// CodeAmendment v1 (CA-5.3) — canonical regression-watcher CLI.
//
// PURPOSE
// ───────
// Long-lived background process the operator runs alongside their
// Ion Swap backend. Polls the indexer for:
//
//   (a) every `code_push_authorized` event in the last 7 days, and
//   (b) every `code_amendment_dry_run_result` event referencing
//       those proposals,
//
// then runs `backend/code-amendments/regression-watcher.js::decideRollback`
// to decide whether the post-push dry-runs show a regression that
// warrants an EMERGENCY_ROLLBACK. If yes, this script broadcasts a
// FROST-signed `EMERGENCY_ROLLBACK` attestation with `autoSpawned:true`.
//
// FROST QUORUM
// ────────────
// Multiple operators running this script INDEPENDENTLY reach the
// same decision (the deciding function is pure). Each operator's
// instance produces a FROST share for the rollback's `relayerSig`;
// the aggregate signature is what authorizes the on-chain rollback.
//
// The FROST signing ceremony is delegated to the existing bridge
// FROST primitives (per Ion Swap rule 110e). This script's job is
// to (a) decide, (b) sign, (c) coordinate via the bridge FROST mesh,
// (d) broadcast.
//
// SAFETY
// ──────
//   • Decision is PURE — same chain state → same verdict on every
//     operator host. Cross-operator divergence is impossible barring
//     a bug in `regression-watcher.js`.
//   • Refuses to broadcast without operator confirmation
//     (CA_REGRESSION_AUTOSPAWN=1 skips the prompt; default is
//     interactive).
//   • Sentinel-tracked: each proposalHash gets one rollback emission
//     locally; re-ticks don't re-spawn.
//
// ENV
// ───
//   CA_REGRESSION_INDEXER_URL    — Ion Swap indexer base URL
//                                  (default https://ion.monerousd.org)
//   CA_REGRESSION_POLL_SECS      — poll interval (default 120)
//   CA_REGRESSION_AUTOSPAWN      — set '1' to skip interactive
//                                  confirmation (recommended for
//                                  unattended production)
//   CA_REGRESSION_OPERATOR_ID    — operator ID for shouldDriveAsPrimary
//                                  gating (rule 116). Same env var as
//                                  the rest of the protocol.
//   CA_REGRESSION_SENTINEL_DIR   — local sentinel directory
//                                  (default ~/.monerousd/ca-regression/)
//   CA_REGRESSION_PRIOR_CODE_HASH_LOOKUP_URL — optional URL the
//                                  watcher hits to resolve the
//                                  pre-push code hash for the
//                                  EMERGENCY_ROLLBACK payload.
//                                  When unset, requires manual
//                                  per-incident hash lookup.

import path     from 'node:path';
import fs       from 'node:fs';
import os       from 'node:os';
import process  from 'node:process';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const __dirname    = path.dirname(fileURLToPath(import.meta.url));
const INDEXER_URL  = process.env.CA_REGRESSION_INDEXER_URL || 'https://ion.monerousd.org';
const POLL_SECS    = Number(process.env.CA_REGRESSION_POLL_SECS || '120');
const AUTOSPAWN    = process.env.CA_REGRESSION_AUTOSPAWN === '1';
const SENTINEL_DIR = process.env.CA_REGRESSION_SENTINEL_DIR
                     || path.join(os.homedir(), '.monerousd', 'ca-regression');
const PRIOR_HASH_LOOKUP_URL = process.env.CA_REGRESSION_PRIOR_CODE_HASH_LOOKUP_URL || '';

function fail(msg) {
  console.error('[regression-watcher] FATAL:', msg);
  process.exit(1);
}

try { fs.mkdirSync(SENTINEL_DIR, { recursive: true, mode: 0o700 }); }
catch (e) { fail(`cannot create SENTINEL_DIR ${SENTINEL_DIR}: ${e.message}`); }

// ── Indexer queries ──────────────────────────────────────────────

async function fetchRecentPushAuthorizations() {
  const r = await fetch(`${INDEXER_URL}/v1/code-amendments/events?types=code_push_authorized`, {
    signal: AbortSignal.timeout(30_000),
  });
  if (!r.ok) throw new Error(`indexer:HTTP_${r.status}`);
  const j = await r.json();
  return Array.isArray(j?.events) ? j.events : [];
}

async function fetchDryRunsForProposal(proposalHash) {
  const r = await fetch(`${INDEXER_URL}/v1/code-amendments/${proposalHash}/dry-runs`, {
    signal: AbortSignal.timeout(30_000),
  });
  if (!r.ok) return [];
  const j = await r.json();
  return Array.isArray(j?.runs) ? j.runs : [];
}

async function alreadyRolledBack(proposalHash) {
  const r = await fetch(`${INDEXER_URL}/v1/code-amendments/events?types=code_rollback_authorized&target=${proposalHash}`, {
    signal: AbortSignal.timeout(30_000),
  });
  if (!r.ok) return false;
  const j = await r.json();
  return (j?.events || []).some((e) => e.payload?.targetProposalHash === proposalHash);
}

async function lookupPriorCodeHash(proposalHash) {
  if (!PRIOR_HASH_LOOKUP_URL) {
    return null;
  }
  try {
    const r = await fetch(`${PRIOR_HASH_LOOKUP_URL}?proposalHash=${proposalHash}`, {
      signal: AbortSignal.timeout(15_000),
    });
    if (!r.ok) return null;
    const j = await r.json();
    return j?.priorCodeHash || null;
  } catch (_) { return null; }
}

// ── Sentinel tracking ────────────────────────────────────────────

function sentinelPath(proposalHash) {
  return path.join(SENTINEL_DIR, `rollback-${proposalHash}.done`);
}

function alreadySpawned(proposalHash) {
  return fs.existsSync(sentinelPath(proposalHash));
}

function markSpawned(proposalHash, detail) {
  fs.writeFileSync(
    sentinelPath(proposalHash),
    JSON.stringify({ spawnedAt: new Date().toISOString(), ...detail }, null, 2)
  );
}

// ── Interactive confirm ──────────────────────────────────────────

async function confirm(prompt) {
  if (AUTOSPAWN) return true;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(prompt + ' (yes/no): ', (a) => {
      rl.close();
      resolve(a.trim().toLowerCase() === 'yes');
    });
  });
}

// ── Per-event handler ────────────────────────────────────────────

let _decideRollback = null;
async function loadDecisionModule() {
  if (_decideRollback) return _decideRollback;
  // Resolve the backend module relative to this script's location.
  // The script ships alongside ion-monerousd-org/ in the operator's
  // checkout; we walk up + over to the backend file.
  const modPath = path.resolve(__dirname, '..', 'ion-monerousd-org',
    'backend', 'code-amendments', 'regression-watcher.js');
  const mod = await import(modPath);
  _decideRollback = mod.decideRollback;
  return _decideRollback;
}

async function evaluatePush(event) {
  const p = event.payload || {};
  const proposalHash = p.proposalHash;
  if (!proposalHash) return;
  if (alreadySpawned(proposalHash)) return;
  if (await alreadyRolledBack(proposalHash)) {
    markSpawned(proposalHash, { result: 'already_rolled_back' });
    return;
  }

  const pushAuthorizedAt = Date.parse(p.coolingOffEndsAt) || Date.now();
  const runs = await fetchDryRunsForProposal(proposalHash);

  const decide = await loadDecisionModule();
  const priorCodeHash = await lookupPriorCodeHash(proposalHash);
  const verdict = decide({
    proposalHash,
    runs,
    pushAuthorizedAt,
    nowMs: Date.now(),
    settings: { priorCodeHash },
  });

  if (!verdict.shouldRollback) {
    // Log only for "interesting" decisions (skip the boring
    // "still in window, insufficient data" cases).
    if (verdict.totalRunners > 0) {
      console.log(
        `[regression-watcher] ${proposalHash.slice(0, 12)}…: ` +
        `${verdict.reason} (${verdict.failingRunners.length}/${verdict.totalRunners} runners fail)`
      );
    }
    return;
  }

  console.warn(
    `\n[regression-watcher] REGRESSION DETECTED on proposal ${proposalHash.slice(0, 12)}…\n` +
    `  Reason:          ${verdict.reason}\n` +
    `  Failing runners: ${verdict.failingRunners.length} / ${verdict.totalRunners}\n` +
    `  Failing IDs:     ${verdict.failingRunners.map((s) => s.slice(0, 12)).join(', ')}\n` +
    `  Prior code hash: ${verdict.priorCodeHash || '(NOT RESOLVED — manual lookup required)'}\n`
  );

  if (!verdict.priorCodeHash) {
    // CA-5.3 audit P1-3 — write a NEEDS-ATTENTION sentinel so:
    //   (a) re-ticks don't log the same noise every 120s, and
    //   (b) an operator's log-shipping rules can alert on the
    //       distinctive error code REGRESSION_DETECTED_NO_PRIOR_HASH.
    // The decision is "rollback recommended but cannot dispatch
    // automatically" — silently logging once per tick would mask a
    // real regression behind a config gap. Loud surface + sentinel
    // ensures an operator sees it within their pager cycle.
    console.error(
      `[regression-watcher] REGRESSION_DETECTED_NO_PRIOR_HASH for ${proposalHash.slice(0, 12)}…: ` +
      `${verdict.failingRunners.length}/${verdict.totalRunners} runners failing but ` +
      `CA_REGRESSION_PRIOR_CODE_HASH_LOOKUP_URL is unset. ` +
      `Configure the lookup service OR run the rollback manually via the wallet UI.`
    );
    try {
      const needsPath = path.join(SENTINEL_DIR, `needs-attention-${proposalHash}.json`);
      fs.writeFileSync(needsPath, JSON.stringify({
        firstDetectedAt: new Date().toISOString(),
        reason:          'NO_PRIOR_CODE_HASH_CONFIGURED',
        failingRunners:  verdict.failingRunners,
        totalRunners:    verdict.totalRunners,
        verdictReason:   verdict.reason,
      }, null, 2));
    } catch (e) {
      console.error(`[regression-watcher] failed to write needs-attention sentinel: ${e.message}`);
    }
    // Optional webhook for pager integration. Operator sets
    // CA_REGRESSION_ALERT_WEBHOOK to a POST endpoint that fires
    // off the alert channel (Slack / PagerDuty / etc.).
    const webhook = process.env.CA_REGRESSION_ALERT_WEBHOOK;
    if (webhook) {
      try {
        await fetch(webhook, {
          method:  'POST',
          headers: { 'content-type': 'application/json' },
          body:    JSON.stringify({
            type:           'REGRESSION_DETECTED_NO_PRIOR_HASH',
            proposalHash,
            failingRunners: verdict.failingRunners.map((s) => s.slice(0, 12)),
            totalRunners:   verdict.totalRunners,
          }),
          signal: AbortSignal.timeout(10_000),
        });
      } catch (e) {
        console.error(`[regression-watcher] alert webhook failed: ${e.message}`);
      }
    }
    // Mark spawned so we don't re-log every tick. The needs-
    // attention sentinel is the operator-visible signal.
    markSpawned(proposalHash, {
      result: 'needs_attention_no_prior_hash',
      verdict,
    });
    return;
  }

  const ok = await confirm(
    `\nAuto-spawn EMERGENCY_ROLLBACK for ${proposalHash.slice(0, 12)}…?`
  );
  if (!ok) {
    console.log('[regression-watcher] operator declined rollback.');
    return;
  }

  // The actual FROST signing + broadcast is operator infrastructure
  // (bridge-frost-* primitives + the CA-UI-Wire-Everything CLI
  // scripts/code-amendment-relayer-broadcast.js). Sentinel-mark the
  // proposal so we don't re-evaluate every tick; emit the directive
  // to a file the operator's signing infrastructure picks up.
  //
  // Dispatch file shape mirrors the
  // code-amendment-relayer-broadcast.js `rollback` subcommand args
  // so the operator can pipe directly:
  //
  //   REASON_FILE=$(mktemp); jq -r .rollbackReasonMd dispatch-*.json > $REASON_FILE
  //   node scripts/code-amendment-relayer-broadcast.js rollback \
  //     --target-proposal-hash=<from dispatch> \
  //     --prior-code-hash=<from dispatch> \
  //     --reason-md-file=$REASON_FILE \
  //     --relayer-sig=<aggregate FROST sig from out-of-band ceremony> \
  //     --stage
  const dispatchPath = path.join(SENTINEL_DIR, `dispatch-${proposalHash}.json`);
  const reasonMd     = `CA-5.3 regression watcher auto-detected post-push failures.\n\n` +
                       `${verdict.failingRunners.length} of ${verdict.totalRunners} independent runners ` +
                       `reported \`fail\` after the push at ${new Date(pushAuthorizedAt).toISOString()}.`;
  fs.writeFileSync(dispatchPath, JSON.stringify({
    targetProposalHash: proposalHash,
    priorCodeHash:      verdict.priorCodeHash,
    rollbackReasonMd:   reasonMd,
    autoSpawned:        true,
    failingRunners:     verdict.failingRunners,
    decidedAt:          new Date().toISOString(),
    // Suggested CLI invocation (informational; pipes-friendly for
    // operator log shipping):
    suggestedCli:       'scripts/code-amendment-relayer-broadcast.js rollback '
                      + `--target-proposal-hash=${proposalHash} `
                      + `--prior-code-hash=${verdict.priorCodeHash} `
                      + '--reason-md-file=<path> '
                      + '--relayer-sig=<from FROST ceremony> '
                      + '--stage',
  }, null, 2));

  console.log(`[regression-watcher] dispatch written to ${dispatchPath}`);
  console.log(`[regression-watcher] next: run FROST ceremony for the relayer sig, then`);
  console.log(`[regression-watcher]   node scripts/code-amendment-relayer-broadcast.js rollback \\`);
  console.log(`[regression-watcher]     --target-proposal-hash=${proposalHash.slice(0, 12)}… --prior-code-hash=… \\`);
  console.log(`[regression-watcher]     --reason-md-file=<path> --relayer-sig=<128hex> --stage`);

  markSpawned(proposalHash, {
    result: 'dispatched',
    dispatchPath,
    verdict,
  });
}

// ── Main loop ────────────────────────────────────────────────────

async function tick() {
  try {
    const events = await fetchRecentPushAuthorizations();
    for (const e of events) {
      await evaluatePush(e);
    }
  } catch (e) {
    console.error('[regression-watcher] tick error:', e.message);
  }
}

console.log(
  `[regression-watcher] started. indexer=${INDEXER_URL} poll=${POLL_SECS}s ` +
  `autospawn=${AUTOSPAWN} sentinel=${SENTINEL_DIR}`
);
await tick();
setInterval(tick, POLL_SECS * 1000);
