// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/* contracts-client.js — failover reader for the DC /v1/contracts/* surface.
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT this is: a decentralization-first, fail-over read client for the Dark
 * Contracts indexer endpoints the IDE polls after a deploy/call:
 *
 *     GET /v1/contracts
 *     GET /v1/contracts/:id
 *     GET /v1/contracts/:id/state
 *     GET /v1/contracts/:id/calls
 *     GET /v1/contracts/by-tx/:hash
 *
 * WHO calls it: pages/deploy.js (materialization polling + state refresh).
 *
 * WHY it exists (decentralization pillar): the IDE previously hard-pinned a
 * SINGLE indexer (`https://ion.monerousd.org`) for every contract read. A lone
 * operator that can be taken down — or that can lie — is a decentralization gap
 * (the same gap the shared SDK calls out for the daemon). This client takes a
 * LIST of indexer URLs and rotates to the next on failure, so a user can run
 * their own `monerousd-indexer` (DC-protocol v1 is operator-agnostic by spec)
 * and the IDE keeps working if ion.monerousd.org is unreachable. It is the
 * `/v1/contracts/*` analogue of the SDK's `FailoverDagPqClient` (which fails
 * over the daemon JSON-RPC / PQ REST surface).
 *
 * NO-HALTS: a failing read against one indexer throws for THAT call only and
 * rotates to the next; it never wedges the caller. NO silent downgrade — if
 * every indexer fails, the caller gets a clear aggregated error and the UI
 * surfaces an explorer fallback (deploy.js rule 17), never a fake "materialized".
 *
 * WRITES never come here. Per IDE-1, every chain-touching WRITE goes through
 * `window.monerousd` (the wallet). This module is READ-ONLY (a view layer),
 * exactly like the indexer it reads.
 */

/** Normalize a single URL or a comma/space/newline-separated list into an
 *  ordered, de-duplicated array of indexer base URLs (trailing slashes
 *  stripped). Empty / falsy entries are dropped. */
export function parseIndexerList(value) {
  if (Array.isArray(value)) {
    return dedupe(value.map(cleanUrl).filter(Boolean));
  }
  if (typeof value === 'string') {
    return dedupe(
      value
        .split(/[\s,]+/)
        .map(cleanUrl)
        .filter(Boolean)
    );
  }
  return [];
}

function cleanUrl(u) {
  if (!u || typeof u !== 'string') return '';
  return u.trim().replace(/\/+$/, '');
}

function dedupe(arr) {
  const seen = new Set();
  const out = [];
  for (const u of arr) {
    if (!seen.has(u)) {
      seen.add(u);
      out.push(u);
    }
  }
  return out;
}

/* ─── ContractsClient — failover GET over the /v1/contracts/* surface ───────── */

export class ContractsClient {
  /**
   * @param {string|string[]} indexers one URL or a list to fail over across
   * @param {object} [opts] { timeoutMs?, fetch? }
   */
  constructor(indexers, opts = {}) {
    this.indexers = parseIndexerList(indexers);
    if (this.indexers.length === 0) {
      // Fail loud rather than silently default to a single hard-pinned operator.
      throw new Error(
        'ContractsClient: no indexer URL configured. Set at least one in ' +
          'Settings → Indexer (multiple, comma-separated, enables failover).'
      );
    }
    this.timeoutMs = opts.timeoutMs || 12000;
    this._fetch = opts.fetch || (typeof fetch === 'function' ? fetch : null);
    if (!this._fetch) {
      throw new Error('ContractsClient: global fetch unavailable');
    }
    this._idx = 0; // sticky: stay on the indexer that last worked
  }

  /** The indexer URL currently preferred (last one that worked). */
  get activeIndexer() {
    return this.indexers[this._idx % this.indexers.length];
  }

  /**
   * GET a path across all configured indexers, rotating on failure.
   * Returns the parsed JSON of the first indexer that answers 2xx.
   * A 404 is treated as a SUCCESSFUL "not found yet" answer (returns null) so
   * materialization polling doesn't pointlessly rotate while a deploy is still
   * confirming on the indexer that's actually tracking it.
   * Throws an aggregated error only if EVERY indexer fails at the transport
   * level (network / 5xx). Fail-closed for the caller's UI, never a fake.
   * @param {string} path e.g. `/v1/contracts/dc1_…`
   * @returns {Promise<object|null>}
   */
  async getJson(path) {
    const n = this.indexers.length;
    const errs = [];
    for (let i = 0; i < n; i++) {
      const base = this.indexers[(this._idx + i) % n];
      const url = `${base}${path.startsWith('/') ? '' : '/'}${path}`;
      try {
        const controller =
          typeof AbortController === 'function' ? new AbortController() : null;
        const timer = controller ? setTimeout(() => controller.abort(), this.timeoutMs) : null;
        let res;
        try {
          res = await this._fetch(url, {
            headers: { Accept: 'application/json' },
            cache: 'no-store',
            signal: controller ? controller.signal : undefined,
          });
        } finally {
          if (timer) clearTimeout(timer);
        }
        if (res.status === 404) {
          // Definitive "not seen yet" from a reachable indexer — stick to it.
          this._idx = (this._idx + i) % n;
          return null;
        }
        if (!res.ok) {
          errs.push(`${base}: HTTP ${res.status}`);
          continue; // transient — try the next indexer
        }
        const json = await res.json();
        this._idx = (this._idx + i) % n; // sticky success
        return json;
      } catch (e) {
        errs.push(`${base}: ${e && e.message ? e.message : e}`);
      }
    }
    throw new Error(
      `ContractsClient: all ${n} indexer(s) failed for ${path} — ${errs.join('; ')}`
    );
  }

  /** GET /v1/contracts/:id — the contract row (abi, codeHash, block, …). */
  getContract(contractId) {
    return this.getJson(`/v1/contracts/${encodeURIComponent(contractId)}`);
  }

  /** GET /v1/contracts/:id/state — public slots raw, private slots as
   *  commitment hex + rangeProofHash (DC-6 — never plaintext). */
  getContractState(contractId) {
    return this.getJson(`/v1/contracts/${encodeURIComponent(contractId)}/state`);
  }

  /** GET /v1/contracts/:id/calls — the call log for a contract. */
  getContractCalls(contractId) {
    return this.getJson(`/v1/contracts/${encodeURIComponent(contractId)}/calls`);
  }

  /** GET /v1/contracts/by-tx/:hash — resolve a deploy carrier tx → contractId. */
  getContractByTx(txHash) {
    return this.getJson(`/v1/contracts/by-tx/${encodeURIComponent(txHash)}`);
  }

  /** GET /v1/contracts — the full deployed-contract list. */
  listContracts() {
    return this.getJson('/v1/contracts');
  }
}
