#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// scripts/frost-validator-auto-grow.js
//
// CA-UI-Wire-Everything (2026-05-18) — auto-grow daemon for the
// FROST custody validator set. Watches the chain for `applied`
// validator applications, decides eligibility per
// `backend/bridge/auto-grow-decide.js`, and either:
//
//   --review  (default)  — writes a dispatch file the operator's
//                          orchestrator picks up to run the DKG2-add
//                          ceremony manually. Safest mode for
//                          Phase 1 solo-bootstrap operators.
//
//   --auto               — invokes scripts/migration-real/run-dkg2-add-ceremony.js
//                          directly + calls approveApplication on
//                          success. Required for the Phase 2+
//                          "automatic admission" property (rule 110e):
//                          "Operator-curated validator selection is
//                          FORBIDDEN after Phase 2". --auto mode
//                          ENFORCES that — once running, the operator
//                          cannot pick-and-choose which applicants
//                          are admitted; the algorithm decides.
//
// WHY THE DAEMON, NOT THE CEREMONY CLI ITSELF
// ────────────────────────────────────────────
// The DKG2-add ceremony coordinates state across ALL existing share-
// holders — every operator's share file must be rotated to the new
// (t', n') topology. The ceremony CLI is a single-host operation;
// the daemon's job is the OUT-OF-BAND COORDINATION: detect the
// eligible applicant, signal the existing operators to run their
// half, wait for the multi-party result, then update the chain
// state. In solo bootstrap (1 operator owns all 3 shares) the
// daemon shortcut runs the ceremony directly. In Phase 2+ multi-
// operator deployments, the daemon writes a dispatch file that
// each operator's instance picks up; each runs the ceremony CLI
// against their own share file; the resulting share rotation is
// distributed through the frost-mesh-protocol.
//
// SAFETY
// ──────
//   • In --review mode (default), NOTHING is broadcast or admitted
//     without operator action. The daemon just decides + logs.
//   • In --auto mode, every admission is gated by the pure
//     `decideEligibleApplications` deriver (algorithmic, no
//     operator-curation per rule 110e).
//   • Cycle cap (default 1 admit per cycle) keeps growth slow so
//     the operator can observe each new validator's behavior
//     before the next admit.
//   • Cooldown (10 min default) defeats front-running between
//     two near-simultaneous BOND_APPLY broadcasts.
//   • The daemon NEVER touches share material directly. It only
//     reads chain state + writes dispatch files + (in --auto)
//     invokes the existing ceremony CLI with operator-configured
//     env vars (share-file paths). The operator controls share
//     storage; the daemon orchestrates the public on-chain steps.
//
// ENV
// ───
//   AUTO_GROW_INDEXER_URL        — Ion Swap indexer (default https://ion.monerousd.org)
//   AUTO_GROW_POLL_SECS          — poll interval (default 300 = 5 min)
//   AUTO_GROW_DISPATCH_DIR       — local dispatch sentinel directory
//                                  (default ~/.monerousd/frost-auto-grow/)
//   AUTO_GROW_MAX_ADMITS_PER_CYCLE — admit cap per tick (default 1)
//   AUTO_GROW_CEREMONY_CLI       — full path to run-dkg2-add-ceremony.js
//                                  (default <repo>/scripts/migration-real/run-dkg2-add-ceremony.js)
//   AUTO_GROW_OPERATOR_BACKEND_URL — backend admin URL for calling
//                                  approveApplication after ceremony
//                                  success (HMAC-gated per rule 73).
//                                  Required for --auto.
//   AUTO_GROW_ADMIN_HMAC_KEY     — HMAC key for admin endpoint
//                                  (operator secret; required for --auto).

import path     from 'node:path';
import fs       from 'node:fs';
import os       from 'node:os';
import crypto   from 'node:crypto';
import process  from 'node:process';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const INDEXER_URL          = process.env.AUTO_GROW_INDEXER_URL || 'https://ion.monerousd.org';
const POLL_SECS            = Number(process.env.AUTO_GROW_POLL_SECS || '300');
const DISPATCH_DIR         = process.env.AUTO_GROW_DISPATCH_DIR
                             || path.join(os.homedir(), '.monerousd', 'frost-auto-grow');
const MAX_ADMITS_PER_CYCLE = Math.max(1, Number(process.env.AUTO_GROW_MAX_ADMITS_PER_CYCLE || '1'));
const CEREMONY_CLI         = process.env.AUTO_GROW_CEREMONY_CLI
                             || path.resolve(__dirname, '..', 'ion-monerousd-org',
                                  'scripts', 'migration-real', 'run-dkg2-add-ceremony.js');
const OPERATOR_BACKEND_URL = process.env.AUTO_GROW_OPERATOR_BACKEND_URL || '';
const ADMIN_HMAC_KEY       = process.env.AUTO_GROW_ADMIN_HMAC_KEY       || '';

function fail(msg) {
  console.error('[frost-auto-grow] FATAL:', msg);
  process.exit(1);
}

const argv = process.argv.slice(2);
const MODE_AUTO    = argv.includes('--auto');
const MODE_REVIEW  = argv.includes('--review') || !MODE_AUTO; // review is the safe default
const ONCE_FLAG    = argv.includes('--once');
const VERBOSE_FLAG = argv.includes('--verbose');

if (MODE_AUTO && !OPERATOR_BACKEND_URL) {
  fail('--auto requires AUTO_GROW_OPERATOR_BACKEND_URL (the admin endpoint for approveApplication)');
}
if (MODE_AUTO && !ADMIN_HMAC_KEY) {
  fail('--auto requires AUTO_GROW_ADMIN_HMAC_KEY (operator secret for admin HMAC)');
}

try { fs.mkdirSync(DISPATCH_DIR, { recursive: true, mode: 0o700 }); }
catch (e) { fail(`cannot create AUTO_GROW_DISPATCH_DIR ${DISPATCH_DIR}: ${e.message}`); }

// ── Backend imports — load lazily so the script doesn't crash on
//    a partial operator checkout (missing ion-monerousd-org/).

let _deciderModule = null;
let _bondEconomicsModule = null;

async function loadBackendModules() {
  if (_deciderModule && _bondEconomicsModule) return;
  // The script ships in two layouts:
  //   1. Operator-local checkout: scripts/ next to ion-monerousd-org/
  //      → backend at __dirname/../ion-monerousd-org/backend/bridge/
  //   2. VPS systemd deploy: /opt/ion-monerousd-org/scripts/ flat
  //      with /opt/ion-monerousd-org/backend/
  //      → backend at __dirname/../backend/bridge/
  // Try both. Fail loudly if neither resolves.
  function _findBackend(relPath) {
    const candidates = [
      path.resolve(__dirname, '..', 'ion-monerousd-org', relPath),  // operator dev
      path.resolve(__dirname, '..', relPath),                       // VPS deploy
    ];
    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }
    return null;
  }
  const deciderPath   = _findBackend('backend/bridge/auto-grow-decide.js');
  const economicsPath = _findBackend('backend/bridge/bond-economics.js');
  if (!deciderPath) {
    fail('backend decider not found at any of:\n'
       + `  ${path.resolve(__dirname, '..', 'ion-monerousd-org', 'backend', 'bridge', 'auto-grow-decide.js')}\n`
       + `  ${path.resolve(__dirname, '..', 'backend', 'bridge', 'auto-grow-decide.js')}`);
  }
  if (!economicsPath) {
    fail('backend bond-economics not found at any candidate path');
  }
  _deciderModule       = await import(deciderPath);
  _bondEconomicsModule = await import(economicsPath);
}

// ── Indexer queries ──────────────────────────────────────────────

async function fetchApplications() {
  // The validator-applications endpoint is operator-only (HMAC-gated)
  // per the public surface limit in rule 110e. The daemon uses the
  // operator's admin endpoint via HMAC; the public /v1/bridge/validator-count
  // is the only unauthenticated read.
  if (!OPERATOR_BACKEND_URL) {
    // --review mode without an admin endpoint reads the indexer's
    // public surface as a best-effort proxy. Operators running real
    // --auto must set AUTO_GROW_OPERATOR_BACKEND_URL anyway.
    return [];
  }
  return adminGet('/api/admin/bridge/validator-applications?status=applied');
}

async function fetchActiveValidatorCount() {
  try {
    const r = await fetch(`${INDEXER_URL}/v1/bridge/validator-count`, {
      signal: AbortSignal.timeout(15_000),
    });
    if (!r.ok) return 0;
    const j = await r.json();
    return Number(j.active_validators || 0);
  } catch (_) {
    return 0;
  }
}

async function fetchDynamicMin() {
  // The dynamic minimum is derived from chain state (TVL × multiplierBps).
  // Read it from the backend via /api/admin/bridge/required-min-bond if
  // exposed, otherwise compute locally via the bond-economics module.
  // For the daemon, we always defer to the backend so multi-operator
  // dispatch reads a consistent snapshot.
  if (OPERATOR_BACKEND_URL) {
    try {
      const j = await adminGet('/api/admin/bridge/required-min-bond');
      if (j && j.requiredAtomic) return String(j.requiredAtomic);
    } catch (_) { /* fall back */ }
  }
  // Local fallback — only correct on the operator's own host where
  // the indexer DB is available.
  await loadBackendModules();
  const r = await _bondEconomicsModule.getRequiredMinBondAtomic({ openSlots: MAX_ADMITS_PER_CYCLE });
  return String(r.requiredAtomic);
}

// ── Admin HMAC client (rule 73) ──────────────────────────────────
//
// CONTRACT (must match backend/bridge/validator-routes.js + backend/server.js):
//   - Timestamp is MILLISECONDS since epoch (NOT seconds). The backend
//     does `Math.abs(Date.now() - ts) > 60_000` so any mismatch in
//     scale fails the replay window check.
//   - Headers are `x-ion-admin-ts` + `x-ion-admin-sig` (NOT bare
//     `x-admin-*`).
//   - The signed `path` is Express's `req.path` — it strips the
//     query string. The daemon MUST sign over the path-only form,
//     not the full URL path+query, or the recomputed MAC differs.
//   - Body for GET is the empty string. Body for POST is the
//     JSON-stringified payload, matching what Express sees after
//     `express.json()` re-serializes the parsed body (rule 114).

function buildAdminAuth(method, urlPath, bodyStr) {
  // Strip the query string from the signed path — Express's
  // `req.path` doesn't include it. The full urlPath (with query)
  // is still used in the URL, just not in the HMAC challenge.
  const signedPath = urlPath.split('?')[0];
  const ts = String(Date.now());
  const challenge = `${ts}\n${method}\n${signedPath}\n${bodyStr || ''}`;
  const mac = crypto.createHmac('sha256', ADMIN_HMAC_KEY).update(challenge).digest('hex');
  return { 'x-ion-admin-ts': ts, 'x-ion-admin-sig': mac };
}

async function adminGet(urlPath) {
  const url = OPERATOR_BACKEND_URL.replace(/\/$/, '') + urlPath;
  const headers = ADMIN_HMAC_KEY ? buildAdminAuth('GET', urlPath, '') : {};
  const r = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) });
  if (!r.ok) {
    const text = await r.text().catch(() => '<no body>');
    throw new Error(`admin GET ${urlPath} HTTP_${r.status}: ${text.slice(0, 300)}`);
  }
  return r.json();
}

async function adminPost(urlPath, body) {
  const url = OPERATOR_BACKEND_URL.replace(/\/$/, '') + urlPath;
  // Match the backend's req.body re-serialization: empty object → '',
  // anything else → JSON. Per rule 114 the canonicalization MUST match.
  const bodyStr = body && Object.keys(body).length > 0 ? JSON.stringify(body) : '';
  const headers = {
    'content-type': 'application/json',
    ...buildAdminAuth('POST', urlPath, bodyStr),
  };
  const r = await fetch(url, {
    method: 'POST', headers, body: bodyStr || '{}',
    signal: AbortSignal.timeout(60_000),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => '<no body>');
    throw new Error(`admin POST ${urlPath} HTTP_${r.status}: ${text.slice(0, 300)}`);
  }
  return r.json().catch(() => ({}));
}

// ── Dispatch + sentinel tracking ─────────────────────────────────

function dispatchPath(stealth) {
  // Use a stealth fingerprint (first 16 chars) for filename to avoid
  // base58 chars colliding with filesystem rules. Full stealth is
  // inside the JSON payload.
  const fp = String(stealth || '').slice(0, 32);
  return path.join(DISPATCH_DIR, `dispatch-${fp}.json`);
}

function alreadyDispatched(stealth) {
  return fs.existsSync(dispatchPath(stealth));
}

function writeDispatch(stealth, decision, topology) {
  fs.writeFileSync(dispatchPath(stealth), JSON.stringify({
    spawnedAt: new Date().toISOString(),
    applicantStealth: stealth,
    decision,
    topology,
    mode: MODE_AUTO ? 'auto' : 'review',
    suggestedCli: 'scripts/migration-real/run-dkg2-add-ceremony.js'
      + ` (DKG2_NEW_VALIDATOR_ID=${topology.nPrime}`
      + ` DKG2_NEW_THRESHOLD=${topology.tPrime})`,
  }, null, 2));
}

// ── Ceremony invocation (--auto mode) ────────────────────────────

async function invokeCeremony({ stealth, topology }) {
  // The ceremony CLI is operator-host-specific (needs the share
  // files + secure host). The daemon DOES NOT bake in the share-
  // file paths — it ONLY passes the topology params + lets the
  // operator's environment supply DKG2_OLD_SHARE_FILES + DKG2_OUT_DIRS.
  //
  // Two failure modes the daemon HAS to surface loudly:
  //   1. Operator forgot to set DKG2_OLD_SHARE_FILES — the ceremony
  //      will fail with a clear error. Daemon should not silently
  //      retry — that'd burn through the cycle cap on a config
  //      issue.
  //   2. Ceremony succeeds but approveApplication call fails (admin
  //      endpoint down). Operator must manually run approveApplication
  //      afterward; the sentinel records the state.
  return new Promise((resolve, reject) => {
    const childEnv = {
      ...process.env,
      DKG2_NEW_VALIDATOR_ID: String(topology.nPrime),
      DKG2_NEW_THRESHOLD:    String(topology.tPrime),
      DKG2_SESSION_ID:       crypto.randomBytes(16).toString('hex'),
    };
    const child = spawn('node', [CEREMONY_CLI], {
      env:   childEnv,
      stdio: 'inherit',
    });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`ceremony CLI exited with code ${code}`));
    });
  });
}

async function approveApplicationOnBackend(stealth) {
  return adminPost('/api/admin/bridge/validator-applications/approve', {
    stealth,
    reviewNotes: 'Approved automatically by frost-validator-auto-grow ('
               + (MODE_AUTO ? '--auto' : '--review') + ') at '
               + new Date().toISOString(),
  });
}

// ── Per-decision handlers ────────────────────────────────────────

async function handleAdmit(decision, topology) {
  const { stealth, reason } = decision;
  if (alreadyDispatched(stealth)) {
    if (VERBOSE_FLAG) console.log(`[frost-auto-grow] ${stealth.slice(0, 16)}… already dispatched`);
    return;
  }
  console.log(`\n[frost-auto-grow] ADMIT eligible applicant ${stealth.slice(0, 16)}…`);
  console.log(`[frost-auto-grow]   reason: ${reason}`);
  console.log(`[frost-auto-grow]   target topology: n=${topology.n} → n'=${topology.nPrime} (t'=${topology.tPrime})`);

  writeDispatch(stealth, decision, topology);
  console.log(`[frost-auto-grow]   dispatch sentinel: ${dispatchPath(stealth)}`);

  if (!MODE_AUTO) {
    console.log(`[frost-auto-grow]   --review mode: operator must run the ceremony manually:`);
    console.log(`[frost-auto-grow]     DKG2_NEW_VALIDATOR_ID=${topology.nPrime} DKG2_NEW_THRESHOLD=${topology.tPrime} \\`);
    console.log(`[frost-auto-grow]     DKG2_OLD_SHARE_FILES=<paths> DKG2_OUT_DIRS=<dirs> \\`);
    console.log(`[frost-auto-grow]     node ${CEREMONY_CLI}`);
    console.log(`[frost-auto-grow]   then: curl -X POST <backend>/api/admin/bridge/validator-applications/approve -d '{"stealth":"${stealth.slice(0, 20)}…"}'`);
    return;
  }

  // --auto mode: invoke ceremony + approve via backend.
  try {
    console.log(`[frost-auto-grow]   --auto: invoking ${CEREMONY_CLI}…`);
    await invokeCeremony({ stealth, topology });
    console.log(`[frost-auto-grow]   ceremony succeeded; approving on backend…`);
    const result = await approveApplicationOnBackend(stealth);
    console.log(`[frost-auto-grow]   ✓ approved. response:`, JSON.stringify(result));
  } catch (e) {
    console.error(`[frost-auto-grow]   --auto FAILED for ${stealth.slice(0, 16)}…: ${e.message}`);
    console.error(`[frost-auto-grow]   the dispatch sentinel is preserved; operator must intervene.`);
  }
}

function handleReject(decision) {
  if (!VERBOSE_FLAG) return;
  console.log(`[frost-auto-grow] ${decision.decision} ${decision.stealth.slice(0, 16)}…: ${decision.reason}`);
}

function handleHold(decision) {
  if (!VERBOSE_FLAG) return;
  console.log(`[frost-auto-grow] ${decision.decision} ${decision.stealth.slice(0, 16)}…: ${decision.reason}`);
}

// ── Main tick ────────────────────────────────────────────────────

async function tick() {
  try {
    await loadBackendModules();
    const applications = await fetchApplications();
    if (applications.length === 0) {
      if (VERBOSE_FLAG) console.log('[frost-auto-grow] no pending applications');
      return;
    }
    const currentValidatorCount = await fetchActiveValidatorCount();
    const dynamicMinBondAtomic  = await fetchDynamicMin();
    if (VERBOSE_FLAG) {
      console.log(`[frost-auto-grow] cycle: ${applications.length} applied, `
        + `${currentValidatorCount} active, dynamicMin=${dynamicMinBondAtomic}`);
    }
    const decisions = _deciderModule.decideEligibleApplications({
      applications,
      dynamicMinBondAtomic,
      currentValidatorCount,
      nowMs: Date.now(),
      maxAdmitsPerCycle: MAX_ADMITS_PER_CYCLE,
    });
    let admitIdx = 0;
    for (const d of decisions) {
      if (d.decision === 'admit') {
        const topology = _deciderModule.computeNewTopology({
          currentValidatorCount,
          admitCount: admitIdx + 1,   // (cumulative within this tick — see decider)
        });
        // The topology's nPrime/tPrime reflect ALL admits in this
        // cycle, but the deriver caps at MAX_ADMITS_PER_CYCLE so
        // admitIdx never exceeds the cap.
        await handleAdmit(d, topology);
        admitIdx += 1;
      } else if (d.decision.startsWith('reject')) {
        handleReject(d);
      } else if (d.decision.startsWith('hold')) {
        handleHold(d);
      }
    }
  } catch (e) {
    console.error('[frost-auto-grow] tick error:', e.message);
    if (VERBOSE_FLAG && e.stack) console.error(e.stack);
  }
}

// ── Startup banner + main loop ──────────────────────────────────

console.log(
  `[frost-auto-grow] started. indexer=${INDEXER_URL} poll=${POLL_SECS}s mode=`
  + `${MODE_AUTO ? 'auto' : 'review'} cap=${MAX_ADMITS_PER_CYCLE} dispatch=${DISPATCH_DIR}`
);
if (MODE_REVIEW) {
  console.log('[frost-auto-grow] REVIEW MODE — no admissions broadcast automatically.');
  console.log('[frost-auto-grow] Pass --auto for Phase 2+ automatic admission (rule 110e).');
}

await tick();

if (ONCE_FLAG) {
  console.log('[frost-auto-grow] --once flag set; exiting after first tick.');
  process.exit(0);
}

setInterval(tick, POLL_SECS * 1000);
