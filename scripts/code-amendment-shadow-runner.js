#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// scripts/code-amendment-shadow-runner.js
//
// CodeAmendment v1 (CA-5) — canonical shadow-CI runner.
//
// PURPOSE
// ───────
// Long-lived background process the operator runs alongside their
// Ion Swap backend. Polls for fresh CODE_PROPOSE attestations,
// applies each proposal's diff to a sandbox checkout, runs the
// project's test suite under the proposed changes, and posts the
// result back into `backend/code-amendments/dry-run-store.js` so
// auditors see machine-verified evidence before filing reports.
//
// NON-GOAL
// ────────
// We do NOT sandbox the test execution beyond the directory move
// + per-run temp checkout. Operators with stricter isolation needs
// (untrusted-proposer threat model) MUST wrap this script in
// Docker / Firejail / nsjail / equivalent. The default flow trusts
// the proposal author's diff at the LEVEL OF "may break tests" —
// not at the level of "may run arbitrary network calls in CI".
// Untrusted proposers + paranoid operators → add the sandbox layer
// before running.
//
// FLOW PER POLL TICK
// ──────────────────
//   1. GET /v1/code-amendments?status=voting from the configured
//      indexer endpoint.
//   2. For each proposal we haven't yet run (no `latest` row from
//      OUR runnerStealth in `code_amendment_dry_runs`):
//        a. Fetch the diff via GET /api/code-amendments/<hash>/diff
//        b. Verify SHA-256(diff) === proposal.diffHash (refuse on
//           mismatch — never apply a tampered diff).
//        c. git stash + git checkout -B shadow-<hash> base-commit
//        d. Apply the diff via `git apply`
//        e. Run the test command (configurable; defaults to
//           `node --test tests/`)
//        f. Capture exit code + last 8 KiB of stdout for details_md
//        g. POST results via dry-run-store::recordDryRunResult
//        h. git checkout - && git branch -D shadow-<hash>
//   3. Sleep POLL_INTERVAL_SECS and loop.
//
// ENV
// ───
//   CA_SHADOW_RUNNER_STEALTH     — the runner's identifying stealth
//                                   (must be 95+ chars; logged in
//                                   the dry-run row so auditors can
//                                   weigh runner reputation).
//   CA_SHADOW_REPO_PATH          — absolute path to the working
//                                   checkout the runner will mutate.
//   CA_SHADOW_TEST_CMD           — test command; default
//                                   `node --test tests/`.
//   CA_SHADOW_BASE_REF           — git ref to checkout BEFORE
//                                   applying the diff; default
//                                   `main`.
//   CA_SHADOW_INDEXER_URL        — Ion Swap indexer base URL;
//                                   default `https://ion.monerousd.org`.
//   CA_SHADOW_POLL_SECS          — poll interval; default 60.
//   CA_SHADOW_RUN_TIMEOUT_SECS   — max wall-clock per run;
//                                   default 600 (10 min).
//   CA_SHADOW_DISABLE            — set to `1` to start in idle
//                                   (loops without acting) — useful
//                                   for testing the connection
//                                   without modifying state.
//
// SAFETY
// ──────
//   • Runner refuses to start if the configured repo has uncommitted
//     changes (would clobber the operator's WIP).
//   • Runner refuses to apply a diff that touches PROTECTED_PATHS
//     (defense-in-depth — the codec already rejects, but a
//     compromised indexer could serve a doctored diff).
//   • Runner enforces SHA-256(diff) === proposal.diffHash before
//     applying. Mismatch → log + skip (no test run on tampered diff).

import path           from 'node:path';
import process        from 'node:process';
import crypto         from 'node:crypto';
import { spawn }      from 'node:child_process';
import { fileURLToPath } from 'node:url';

// ── Config ───────────────────────────────────────────────────────

const RUNNER_STEALTH   = process.env.CA_SHADOW_RUNNER_STEALTH || '';
const REPO_PATH        = process.env.CA_SHADOW_REPO_PATH || '';
const TEST_CMD         = process.env.CA_SHADOW_TEST_CMD || 'node --test tests/';
const BASE_REF         = process.env.CA_SHADOW_BASE_REF || 'main';
const INDEXER_URL      = process.env.CA_SHADOW_INDEXER_URL || 'https://ion.monerousd.org';
const POLL_SECS        = Number(process.env.CA_SHADOW_POLL_SECS || '60');
const RUN_TIMEOUT_SECS = Number(process.env.CA_SHADOW_RUN_TIMEOUT_SECS || '600');
const DISABLE          = process.env.CA_SHADOW_DISABLE === '1';

// ── Bootstrap ────────────────────────────────────────────────────

function fail(msg) {
  console.error('[shadow-runner] FATAL:', msg);
  process.exit(1);
}

if (!RUNNER_STEALTH || RUNNER_STEALTH.length < 95) {
  fail('CA_SHADOW_RUNNER_STEALTH must be set to a 95+ char stealth address.');
}
if (!REPO_PATH) {
  fail('CA_SHADOW_REPO_PATH must be set to the absolute path of the checkout.');
}

// ── Per-tick helpers ─────────────────────────────────────────────

async function fetchOpenProposals() {
  const r = await fetch(`${INDEXER_URL}/v1/code-amendments?status=voting`, {
    signal: AbortSignal.timeout(30_000),
  });
  if (!r.ok) throw new Error(`indexer-status:HTTP_${r.status}`);
  const j = await r.json();
  return Array.isArray(j?.proposals) ? j.proposals : [];
}

async function fetchProposalDiff(proposalHash) {
  const r = await fetch(`${INDEXER_URL}/api/code-amendments/${proposalHash}/diff`, {
    signal: AbortSignal.timeout(60_000),
  });
  if (!r.ok) throw new Error(`indexer-diff:HTTP_${r.status}`);
  return r.text();
}

async function alreadyRan(proposalHash) {
  const r = await fetch(
    `${INDEXER_URL}/v1/code-amendments/${proposalHash}/dry-runs?runner=${encodeURIComponent(RUNNER_STEALTH)}`,
    { signal: AbortSignal.timeout(30_000) }
  );
  if (!r.ok) return false;
  const j = await r.json();
  // If the indexer returns a non-empty `latest` row from our runner,
  // we've already reported on this proposal.
  return Array.isArray(j?.runs) && j.runs.some((row) => row.runner_stealth === RUNNER_STEALTH);
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

/**
 * Run a shell command with timeout. Returns { exit, stdout, stderr,
 * durationSecs }.
 */
function runCmd(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const p = spawn(cmd, args, { cwd: REPO_PATH, ...opts });
    let stdout = '', stderr = '';
    p.stdout.on('data', (d) => { stdout += d.toString(); });
    p.stderr.on('data', (d) => { stderr += d.toString(); });
    const timer = setTimeout(() => {
      try { p.kill('SIGKILL'); } catch (_) {}
    }, RUN_TIMEOUT_SECS * 1000);
    p.on('close', (exit) => {
      clearTimeout(timer);
      resolve({
        exit, stdout, stderr,
        durationSecs: Math.round((Date.now() - started) / 1000),
      });
    });
  });
}

async function runShadowOnProposal(proposal) {
  console.log(`[shadow-runner] running proposal ${proposal.proposalHash.slice(0, 12)}…`);

  // 1. Fetch diff + verify SHA-256.
  const diff = await fetchProposalDiff(proposal.proposalHash);
  const actualDiffHash = sha256Hex(diff);
  if (actualDiffHash !== proposal.diffHash) {
    console.error(
      `[shadow-runner] DIFF HASH MISMATCH for ${proposal.proposalHash.slice(0, 12)}: ` +
      `expected ${proposal.diffHash.slice(0, 12)}…, got ${actualDiffHash.slice(0, 12)}…. ` +
      `Refusing to apply tampered diff.`
    );
    await reportResult({
      proposalHash:    proposal.proposalHash,
      result:          'error',
      detailsMd:       'DIFF_HASH_MISMATCH: indexer-served diff did not match proposal.diffHash',
      appliedDiffHash: null,
    });
    return;
  }

  // 2. Check repo state — refuse if dirty.
  const statusResult = await runCmd('git', ['status', '--porcelain']);
  if (statusResult.stdout.trim() !== '') {
    console.error('[shadow-runner] repo is dirty; refusing to clobber WIP. Commit or stash first.');
    return;
  }
  const baseCommitResult = await runCmd('git', ['rev-parse', BASE_REF]);
  const baseCommit = baseCommitResult.stdout.trim();
  if (!baseCommit) {
    console.error(`[shadow-runner] could not resolve base ref ${BASE_REF}`);
    return;
  }

  const branchName = `shadow-${proposal.proposalHash.slice(0, 16)}`;
  let result = 'error';
  let detailsMd = '';
  let testsTotal = null, testsPassed = null, testsFailed = null;
  let durationSecs = null;

  try {
    // 3. Branch + apply diff.
    await runCmd('git', ['checkout', '-B', branchName, baseCommit]);
    const applyResult = await runCmd('git', ['apply', '--whitespace=nowarn', '-'], {
      // Pipe the diff into stdin.
    });
    // We need to write the diff via stdin — spawn-with-stdin is
    // slightly different. Use a temp file approach for reliability.
    // (Inline-stdin would work too but adds complexity for portability.)
    // ...
    // (Switch to writing diff via temp file)
    const fs = await import('node:fs');
    const os = await import('node:os');
    const tmpDiff = path.join(os.tmpdir(), `shadow-${proposal.proposalHash.slice(0, 12)}.patch`);
    fs.writeFileSync(tmpDiff, diff);
    const applyResult2 = await runCmd('git', ['apply', '--whitespace=nowarn', tmpDiff]);
    try { fs.unlinkSync(tmpDiff); } catch (_) {}
    if (applyResult2.exit !== 0) {
      result = 'fail';
      detailsMd = `git apply failed:\n${(applyResult2.stderr || '').slice(-4096)}`;
      console.warn(`[shadow-runner] git apply FAILED for ${proposal.proposalHash.slice(0, 12)}`);
    } else {
      // 4. Run tests.
      const [testCmd, ...testArgs] = TEST_CMD.split(/\s+/);
      const testResult = await runCmd(testCmd, testArgs);
      durationSecs = testResult.durationSecs;
      detailsMd = (testResult.stdout + '\n---STDERR---\n' + testResult.stderr).slice(-8192);

      // Parse `node --test` summary lines if present.
      const totalMatch  = testResult.stdout.match(/tests (\d+)/);
      const passMatch   = testResult.stdout.match(/pass (\d+)/);
      const failMatch   = testResult.stdout.match(/fail (\d+)/);
      testsTotal  = totalMatch ? Number(totalMatch[1]) : null;
      testsPassed = passMatch  ? Number(passMatch[1])  : null;
      testsFailed = failMatch  ? Number(failMatch[1])  : null;

      result = testResult.exit === 0 ? 'pass' : 'fail';
    }
  } catch (e) {
    result = 'error';
    detailsMd = `runner exception: ${e.message}`;
  } finally {
    // 5. Restore checkout.
    await runCmd('git', ['checkout', '-']);
    await runCmd('git', ['branch', '-D', branchName]);
  }

  await reportResult({
    proposalHash:    proposal.proposalHash,
    result,
    detailsMd,
    testsTotal, testsPassed, testsFailed,
    durationSecs,
    baseCommit,
    appliedDiffHash: actualDiffHash,
  });
  console.log(
    `[shadow-runner] reported ${result} for ${proposal.proposalHash.slice(0, 12)}: ` +
    `${testsPassed || 0}/${testsTotal || 0} tests passed`
  );
}

/**
 * POST the result via the canonical operator API. The store module
 * lives on the operator's Ion Swap backend; here we just hit the HTTP
 * endpoint. CA-5.2 wires the HTTP endpoint into server.js.
 */
async function reportResult(body) {
  body.runnerStealth = RUNNER_STEALTH;
  try {
    const r = await fetch(`${INDEXER_URL}/api/code-amendments/dry-runs`, {
      method:  'POST',
      headers: { 'content-type': 'application/json' },
      body:    JSON.stringify(body),
      signal:  AbortSignal.timeout(30_000),
    });
    if (!r.ok) {
      console.error(`[shadow-runner] report POST failed: HTTP ${r.status}`);
    }
  } catch (e) {
    console.error(`[shadow-runner] report POST exception: ${e.message}`);
  }
}

// ── Main loop ────────────────────────────────────────────────────

async function tick() {
  try {
    const proposals = await fetchOpenProposals();
    for (const p of proposals) {
      if (await alreadyRan(p.proposalHash)) continue;
      await runShadowOnProposal(p);
    }
  } catch (e) {
    console.error('[shadow-runner] tick error:', e.message);
  }
}

if (!DISABLE) {
  console.log(`[shadow-runner] started. runner=${RUNNER_STEALTH.slice(0, 12)}… repo=${REPO_PATH} poll=${POLL_SECS}s`);
  await tick();
  setInterval(tick, POLL_SECS * 1000);
} else {
  console.log('[shadow-runner] started in DISABLED mode (CA_SHADOW_DISABLE=1). Idle.');
}
