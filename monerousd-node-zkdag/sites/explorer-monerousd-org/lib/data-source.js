// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// data-source.js — node-first data resolution. There is no server of ours: the chain is read from a node the reader
// runs or trusts.
//
// Priority chain:
//   1. window.monerousd (wallet provider) — inside the wallet, every read goes to the wallet's own node.
//   2. This machine's node (127.0.0.1:27780). Its RPC answers only pages the node itself serves and the wallet
//      (the node's DB-374 origin rule, borrowed from geth's --http.corsdomain), so this works when the explorer is
//      opened from the node's own app server — never from a public web page.
//   3. Same-origin `/v1/*` and `/api/*` — the node's app server serves these beside this page.
// A public copy of this page (GitHub Pages) reaches none of them and says so (`nodeReachable()` false), instead of
// showing empty numbers.
//
// Both lists can be pointed at another node the reader runs: `localStorage.daemon_rpcs_testnet` and
// `localStorage.indexer_endpoints_testnet` (comma-separated URLs).

// ── network selection — URL-path driven (matches Ion Swap) ─────────
//
// Testnet lives at explorer.monerousd.org/testnet — a path PREFIX on
// the SAME origin, so there's no separate nameserver to provision.
// The active network is derived purely from `location.pathname`, so
// the URL is shareable + bookmarkable and a refresh stays on-network.
//
// The data source it talks to follows the same single-origin
// convention the desktop wallet ships (see build-1261/lib/
// network-config.cjs): nginx on ion.monerousd.org reverse-proxies
// `/testnet/*` to the testnet USDmd RPC + testnet ion-backend. No raw
// IPs, no phone-home — privacy-preserving by construction.
// The shared MonerousD DAG/PQ SDK (vendored ESM copy). Surfaces the verified
// live-testnet RPC shapes: GHOSTDAG mergeset (additional_parents), PQ notes,
// the depth-32 PQ output tree, and the hash-tuple settlement anchor. Importing
// it here means the explorer never re-derives DAG/PQ shapes by hand.
import {
  DEFAULT_TESTNET_DAEMON,
  TESTNET_GENESIS_HASH,
  PQ_OUTPUT_TREE_DEPTH,
  normalizeDagBlock,
} from './dag-pq-sdk.js';

export { TESTNET_GENESIS_HASH, PQ_OUTPUT_TREE_DEPTH };

// Mainnet has not launched: there is one chain, the public testnet, and the explorer shows it at its root.
const NETWORKS = {
  testnet: Object.freeze({
    key: 'testnet', label: 'Testnet', basePath: '/',
    daemonRpcs: [DEFAULT_TESTNET_DAEMON],
    indexerEndpoints: [''],
  }),
};

export function getNetwork() { return 'testnet'; }
export function getNetworkConfig() { return NETWORKS.testnet; }
export function getNetworkLabel()  { return NETWORKS.testnet.label; }
export function isTestnet()        { return true; }

function defaultDaemonRpcs()        { return NETWORKS.testnet.daemonRpcs.slice(); }
function defaultIndexerEndpoints()  { return NETWORKS.testnet.indexerEndpoints.slice(); }
function daemonOverrideKey()        { return 'daemon_rpcs_testnet'; }
function indexerOverrideKey()       { return 'indexer_endpoints_testnet'; }

// Can this page read a node at all? One cheap read, remembered for the page's life. Pages use it to show the
// "connect" state instead of a page of dashes.
let _reach = null;
export function nodeReachable() {
  if (!_reach) _reach = getBlockCount().then(() => true, () => false);
  return _reach;
}

// The node's plain REST routes (`/dir/*`, `/ion/*`, `/dag_recent`) — wallet first, then this machine's node.
export async function nodeGet(path, body) {
  const p = provider();
  if (p && typeof p.nodeRpc === 'function') {
    try { return await p.nodeRpc(path, body ? JSON.stringify(body) : ''); } catch (_) { /* this machine's node next */ }
  }
  for (const base of loadList(daemonOverrideKey(), defaultDaemonRpcs())) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), RPC_TIMEOUT_MS);
      const r = await fetch(base.replace(/\/+$/, '') + path, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}), signal: ctrl.signal,
      });
      clearTimeout(t);
      if (r.ok) return await r.json();
    } catch (_) { /* next */ }
  }
  throw new Error('node-unreachable(' + path + ')');
}

const RPC_TIMEOUT_MS = 8_000;
const INDEXER_TIMEOUT_MS = 6_000;

// ── helpers ─────────────────────────────────────────────────────────

function loadList(localStorageKey, defaults) {
  try {
    const raw = localStorage.getItem(localStorageKey);
    if (!raw) return defaults.slice();
    const parsed = raw.split(',').map(s => s.trim()).filter(Boolean);
    return parsed.length ? parsed : defaults.slice();
  } catch (_) { return defaults.slice(); }
}

function shuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// ── source detection ───────────────────────────────────────────────

let _walletProvider = null;
function provider() {
  if (_walletProvider !== null) return _walletProvider;
  try {
    if (typeof window !== 'undefined' && window.monerousd) {
      _walletProvider = window.monerousd;
      return _walletProvider;
    }
  } catch (_) {}
  _walletProvider = false;
  return false;
}

export function getActiveSourceLabel() {
  if (provider()) return 'your wallet’s node';
  return 'your node';
}

// ── daemon RPC ─────────────────────────────────────────────────────

async function callDaemonRpc(method, params) {
  const p = provider();
  if (p && typeof p.daemonRpc === 'function') {
    try {
      return await p.daemonRpc(method, params);
    } catch (e) {
      // Fall through to the federated path; provider may not implement
      // every method (e.g. older wallet builds).
    }
  }

  const endpoints = loadList(daemonOverrideKey(), defaultDaemonRpcs());
  const tried = [];
  for (const base of shuffle(endpoints)) {
    const url = base.replace(/\/+$/, '') + '/json_rpc';
    tried.push(url);
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), RPC_TIMEOUT_MS);
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params: params || {} }),
        signal: ctrl.signal,
      });
      clearTimeout(t);
      if (!resp.ok) continue;
      const j = await resp.json();
      if (j.error) continue;
      return j.result;
    } catch (_) { /* try next */ }
  }
  throw new Error('daemon-rpc-all-endpoints-failed: ' + tried.join(','));
}

// ── indexer ────────────────────────────────────────────────────────

async function callIndexer(path) {
  const p = provider();
  if (p && typeof p.indexerFetch === 'function') {
    try { return await p.indexerFetch(path); }
    catch (_) { /* fall through */ }
  }

  const endpoints = loadList(indexerOverrideKey(), defaultIndexerEndpoints());
  const tried = [];
  for (const base of shuffle(endpoints)) {
    const url = base.replace(/\/+$/, '') + path;
    tried.push(url);
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), INDEXER_TIMEOUT_MS);
      const resp = await fetch(url, { signal: ctrl.signal });
      clearTimeout(t);
      if (!resp.ok) continue;
      return await resp.json();
    } catch (_) { /* try next */ }
  }
  throw new Error('indexer-all-endpoints-failed: ' + tried.join(','));
}

// The node's REAL recent-DAG structure (ids, parent edges, blue scores, selected flags) — the
// honest per-block identity feed. Same-origin sovereign proxy first (the wallet's own node), the
// federated daemon's /dag_recent otherwise. Empty on total miss — callers render "—", never invent.
export async function dagRecent() {
  try {
    const r = await fetch('/api/explorer/dag-recent', { cache: 'no-store' });
    if (r.ok) { const j = await r.json(); if (Array.isArray(j.blocks)) return j.blocks; }
  } catch (_) {}
  for (const base of loadList(daemonOverrideKey(), defaultDaemonRpcs())) {
    try {
      const r = await fetch(base.replace(/\/+$/, '') + '/dag_recent', { cache: 'no-store' });
      if (r.ok) { const j = await r.json(); if (Array.isArray(j.blocks)) return j.blocks; }
    } catch (_) {}
  }
  return [];
}

// ⭐ SATOSHI §10 — the PUBLIC custody figures (SAT base units): total custody weight, the bottom-2/3 effective security, and
// the SAT a newcomer must bond to hold more than 2/3 of custody. Same-origin sovereign proxy first, then the daemon's own route.
// `null` on total miss — callers render "—", never invent. The reserve is confidential and never appears here.
export async function takeoverCost() {
  try {
    const r = await fetch('/api/explorer/takeover-cost', { cache: 'no-store' });
    if (r.ok) { const j = await r.json(); if (j && j.takeover_cost_sat != null) return j; }
  } catch (_) {}
  for (const base of loadList(daemonOverrideKey(), defaultDaemonRpcs())) {
    try {
      const r = await fetch(base.replace(/\/+$/, '') + '/takeover_cost', { cache: 'no-store' });
      if (r.ok) { const j = await r.json(); if (j && j.takeover_cost_sat != null) return j; }
    } catch (_) {}
  }
  return null;
}

// ── public API ─────────────────────────────────────────────────────

// Generic JSON-RPC method passthrough — page modules use this for
// methods without a function of their own (e.g. `get_info`).
// Same failover semantics as the typed wrappers below.
export async function callDaemon(method, params) {
  return callDaemonRpc(method, params || {});
}

// Daemon get_info — chain tip, nettype, top_block_hash, etc. Same daemon
// failover as every other RPC (local 127.0.0.1:28080 first on testnet).
export async function getInfo() {
  return callDaemonRpc('get_info', {});
}

export async function getBlockCount() {
  const r = await callDaemonRpc('get_block_count', {});
  return Number(r.count);
}

// get_block — ALWAYS request decode_as_json so the decoded `json` blob (which
// carries the GHOSTDAG mergeset `additional_parents`) is present. The mergeset
// is NOT in block_header; without decode_as_json the DAG shape is invisible.
export async function getBlockByHeight(height) {
  return callDaemonRpc('get_block', { height: Number(height), decode_as_json: true });
}

export async function getBlockByHash(hash) {
  return callDaemonRpc('get_block', { hash, decode_as_json: true });
}

// getDagBlock — the normalized GHOSTDAG view of a block (selected parent +
// mergeset/additional_parents + the hash-tuple settlement anchor). Pages that
// render the DAG shape use this instead of poking at raw RPC fields.
// `idOrHash` may be a height (number/decimal string) or a 64-hex hash.
export async function getDagBlock(idOrHash) {
  let raw;
  if (typeof idOrHash === 'number' || /^\d+$/.test(String(idOrHash))) {
    raw = await getBlockByHeight(Number(idOrHash));
  } else {
    raw = await getBlockByHash(String(idOrHash));
  }
  return normalizeDagBlock(raw);
}

// ── daemon PQ REST endpoints (non-json_rpc) ────────────────────────
// These hit the daemon's /get_pq_* handlers directly through the SAME daemon
// failover list as callDaemonRpc, so PQ reads are decentralization-respecting
// and never depend on the single-operator indexer. Amounts stay confidential —
// only opaque note blobs / commitment roots are surfaced.
async function callDaemonRest(path, body) {
  const p = provider();
  if (p && typeof p.daemonRest === 'function') {
    try { return await p.daemonRest(path, body || {}); }
    catch (_) { /* fall through to federated */ }
  }
  const endpoints = loadList(daemonOverrideKey(), defaultDaemonRpcs());
  const tried = [];
  for (const base of shuffle(endpoints)) {
    const url = base.replace(/\/+$/, '') + '/' + path.replace(/^\/+/, '');
    tried.push(url);
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), RPC_TIMEOUT_MS);
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body || {}),
        signal: ctrl.signal,
      });
      clearTimeout(t);
      if (!resp.ok) continue;
      const j = await resp.json();
      // Fail-closed on the bad call ONLY (no-halts): a non-OK status rotates
      // to the next peer rather than wedging the page.
      if (j && j.status && j.status !== 'OK') continue;
      return j;
    } catch (_) { /* try next */ }
  }
  throw new Error('daemon-rest-all-endpoints-failed(' + path + '): ' + tried.join(','));
}

// get_pq_output_tree → { count, depth, notes_hex, status }. depth == 32 live.
export async function getPqOutputTree() {
  return callDaemonRest('get_pq_output_tree', {});
}
// get_pq_notes → { notes:[{blob_hex, height}], top_height, status }. Opaque blobs.
export async function getPqNotes(fromHeight = 0) {
  return callDaemonRest('get_pq_notes', { from_height: Number(fromHeight) || 0 });
}
// get_pq_epoch_address → { epoch_address, epoch_b_hex, status }. The rec-block
// (DOMAIN_PQ_REC_BLOCK) carrier address for the current epoch.
export async function getPqEpochAddress() {
  return callDaemonRest('get_pq_epoch_address', {});
}
// get_pq_nf_spent → { status }. Public nullifier spent-set query (double-spend
// / no-inflation gate is daemon-enforced). Soft-fail variant returns null.
export async function getPqNfSpent(nullifiers) {
  return callDaemonRest('get_pq_nf_spent', { nullifiers: nullifiers || [] });
}
// get_pq_username_tree → { count, depth, notes_hex, root_hex, empty_root_hex, status }.
// #77/#80 confidential username market: the daemon's username-IMT. `notes_hex` is the
// concatenation of 32B HIDING uname_cm = Poseidon2(DS_USERNAME||name||owner_pk) leaves —
// serving them leaks NO username↔owner mapping (the whole privacy point). The explorer can
// only show that N names are claimed + the threaded root, never WHICH names or WHO owns them.
export async function getPqUsernameTree() {
  return callDaemonRest('get_pq_username_tree', {});
}
export async function getPqUsernameTreeSafe() {
  try { return await getPqUsernameTree(); } catch (_) { return null; }
}
export async function getPqOutputTreeSafe() {
  try { return await getPqOutputTree(); } catch (_) { return null; }
}
export async function getPqNotesSafe(fromHeight = 0) {
  try { return await getPqNotes(fromHeight); } catch (_) { return null; }
}
export async function getPqEpochAddressSafe() {
  try { return await getPqEpochAddress(); } catch (_) { return null; }
}

// Monero daemons expose `get_transactions` as a NON-JSON-RPC
// endpoint at `/get_transactions` (along with /get_blocks.bin,
// /get_outs, etc — the "common" handlers). Calling it through
// /json_rpc returns "Method not found". Wrapper below mirrors
// the failover loop used by callDaemonRpc but talks to the
// direct endpoint instead.
export async function getTransactions(txHashes) {
  const p = provider();
  if (p && typeof p.daemonRpc === 'function') {
    try {
      // Provider may forward this transparently; older builds
      // may not — soft-fall through to the federated path.
      const r = await p.daemonRpc('get_transactions', {
        txs_hashes: txHashes, decode_as_json: true,
      });
      if (r && (r.txs || r.txs_as_json)) return r;
    } catch (_) {}
  }
  const endpoints = loadList(daemonOverrideKey(), defaultDaemonRpcs());
  const tried = [];
  for (const base of shuffle(endpoints)) {
    const url = base.replace(/\/+$/, '') + '/get_transactions';
    tried.push(url);
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), RPC_TIMEOUT_MS);
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ txs_hashes: txHashes, decode_as_json: true }),
        signal: ctrl.signal,
      });
      clearTimeout(t);
      if (!resp.ok) continue;
      const j = await resp.json();
      if (j.status && j.status !== 'OK') continue;
      return j;
    } catch (_) { /* try next */ }
  }
  throw new Error('get_transactions-all-endpoints-failed: ' + tried.join(','));
}

export async function getRecentBlocks(count) {
  const tip = await getBlockCount();
  const top = tip - 1;
  const out = [];
  // Sequential fetch — fine for top-10 latest. Parallel batched
  // fetch is in the Phase F failover module's roadmap; not needed
  // for the explorer home page yet.
  for (let h = top; h > top - count && h >= 0; h--) {
    try {
      const b = await getBlockByHeight(h);
      out.push(b);
    } catch (_) { break; }
  }
  return out;
}

export async function getActivity(addr) {
  return callIndexer('/v1/activity?addr=' + encodeURIComponent(addr));
}

export async function getTokens() {
  return callIndexer('/v1/tokens');
}

export async function getToken(tokenId) {
  return callIndexer('/v1/tokens/' + encodeURIComponent(tokenId));
}

export async function getPools() {
  return callIndexer('/v1/pools');
}

export async function getPool(poolId) {
  return callIndexer('/v1/pools/' + encodeURIComponent(poolId));
}

export async function getContract(contractId) {
  return callIndexer('/v1/contracts/' + encodeURIComponent(contractId));
}

// Soft-fail variant used by the search index + non-critical UI
// surfaces — returns null on failure instead of throwing, so a
// momentarily-unreachable indexer doesn't break the header dropdown.
export async function callIndexerSafe(path) {
  try { return await callIndexer(path); }
  catch (_) { return null; }
}

// Federated /v1/* fetch used by the new redesign pages (orgs,
// sites, validators, reserve). Adds soft-fail semantics so a page
// can render an empty state instead of a hard error when an
// endpoint isn't deployed yet.
export async function getSites() {
  return callIndexerSafe('/v1/sites');
}
export async function getSitesStats() {
  return callIndexerSafe('/v1/sites/stats');
}
export async function getValidators() {
  return callIndexerSafe('/v1/bridge/validators') ||
         callIndexerSafe('/v1/validators');
}
export async function getReserveSummary() {
  return callIndexerSafe('/v1/reserve/summary');
}
export async function getActivityFeed(limit = 30) {
  return callIndexerSafe('/v1/activity?limit=' + limit);
}

// ── helpers exported for UI ────────────────────────────────────────

export function fmtUsd8(atomic) {
  // 8 decimals everywhere in MoneroUSD per CLAUDE.md atomic-units rule.
  if (atomic == null) return '—';
  const s = String(atomic);
  const big = BigInt(s);
  const whole = big / 100000000n;
  const frac  = (big % 100000000n).toString().padStart(8, '0');
  return whole.toLocaleString('en-US') + '.' + frac;
}

export function shortHash(h, leadingChars = 12, trailingChars = 6) {
  if (!h || typeof h !== 'string') return '—';
  if (h.length <= leadingChars + trailingChars + 3) return h;
  return h.slice(0, leadingChars) + '…' + h.slice(-trailingChars);
}

export function timeAgo(unixSec) {
  if (!unixSec) return '—';
  const diff = Math.floor(Date.now() / 1000) - Number(unixSec);
  if (diff < 0) return 'just now';
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}
