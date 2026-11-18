// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// search-index.js — local autocomplete index for the header search
// dropdown.
//
// What's INDEXED locally (no remote call to suggest):
//   • The native assets (USDm, SAT) and the organizations
//   • Tokens and NFTs from the chain's directory (lib/chain.js), newest first
//   • Sovereign sites from the node's /v1/sites
// A block height, a 64-hex id or an @name is offered as a direct match.

import * as ds from './data-source.js';
import * as chain from './chain.js';
import { NATIVE_ASSETS, VERIFIED_ORGS, logoUrlFor, initials } from './registries.js';

const ENTRIES = [];  // flat list — every searchable item
let _customTokensLoaded = false;
let _sitesLoaded = false;

// Normalize search text so users typing "ionswap" find "Ion Swap"
// (name has a space; slug uses a dash). We collapse whitespace,
// dashes, dots, and underscores into a single tight form, then
// search BOTH the original haystack and the normalized one.
function _normalize(s) {
  return (s || '').toString().toLowerCase().replace(/[\s\-_.]+/g, '');
}

function pushTokenEntry(t, kind, badge) {
  const sym = (t.symbol || t.ticker || '').toString();
  const name = (t.name || sym).toString();
  const haystack = (name + ' ' + sym + ' ' + (t.tokenId || '')).toLowerCase();
  ENTRIES.push({
    kind,                                  // 'token' | 'nft' | 'site' | 'org' | 'custom-token'
    label: name,
    symbol: sym,
    sub: t.tokenId ? t.tokenId.slice(0, 16) + '…' : 'native asset',
    href: '#/token/' + encodeURIComponent(t.tokenId || sym),
    logo: logoUrlFor(t),
    badge: badge || null,
    haystack,
    haystackTight: _normalize(haystack),
    org: t.org || null,
  });
}

function pushOrgEntry(o) {
  const haystack = (o.name + ' ' + o.slug + ' ' + (o.blurb || '')).toLowerCase();
  ENTRIES.push({
    kind: 'org',
    label: o.name,
    symbol: o.slug,
    sub: o.blurb || '',
    href: '#/org/' + encodeURIComponent(o.slug),
    // Use the org's own logo so the dropdown shows the real Ion Swap
    // / MoneroUSD coin instead of letter-initials.
    logo: o.logoUrl || null,
    badge: 'verified',
    haystack,
    haystackTight: _normalize(haystack),
  });
}

function pushSiteEntry(s) {
  const dom = s.domain || s.url || '';
  const haystack = dom.toLowerCase();
  ENTRIES.push({
    kind: 'site',
    label: dom,
    symbol: dom,
    sub: 'v' + (s.version || '?') + ' · ' + (s.publisher ? s.publisher.slice(0, 16) + '…' : ''),
    href: '#/site/' + encodeURIComponent(dom),
    logo: null,
    badge: s.verified ? 'verified' : null,
    haystack,
    haystackTight: _normalize(haystack),
  });
}

for (const t of NATIVE_ASSETS)     pushTokenEntry(t, 'token', 'verified');
for (const o of VERIFIED_ORGS)     pushOrgEntry(o);

// ─── Ecosystem auto-pull ─────────────────────────────────────────
//
// The search index needs to surface newly-launched tokens, newly-
// minted NFT collections, and newly-published sovereign sites in
// real time — so a user typing the symbol of a token that was
// launched 30 s ago still finds it in the dropdown.
//
// We do this via two background loops:
//   1. `loadCustomTokens()` — every TOKEN_REFRESH_MS, hit
//      `/v1/tokens` and upsert any entry whose tokenId isn't
//      already in the index. Same for NFTs (kind === 'nft' filter).
//   2. `loadSites()` — every SITE_REFRESH_MS, hit `/v1/sites` and
//      upsert sovereign-site entries.
//
// Both loops soft-fail: a network blip doesn't drop existing
// entries. Both start IMMEDIATELY at first `primeIndex()` call,
// and re-fire on a setInterval.

const TOKEN_REFRESH_MS = 45_000;   // surface new tokens / NFTs fast
const SITE_REFRESH_MS  = 60_000;   // sovereign-site cadence

// Quick lookup helpers for de-dup.
function _tokenKey(t) {
  return (t.tokenId || t.token_id || t.symbol_public || t.symbol || '').toString();
}
function _siteKey(s) { return (s.domain || s.url || '').toString(); }

const _known = new Set();
async function loadCustomTokens() {
  try {
    if (!(await ds.nodeReachable())) return;
    const r = await chain.scanNewest(e => e.kind === chain.KIND.ASSET, 96);
    for (const e of r.items) {
      const a = chain.parseAssetEntry(e);
      if (_known.has(a.id)) continue;
      _known.add(a.id);
      pushTokenEntry({ symbol: a.symbol, name: a.name || a.symbol, tokenId: a.id }, a.kind === 'nft' ? 'nft' : 'custom-token', null);
    }
    _customTokensLoaded = true;
  } catch (_) {
    // the native assets and organizations stay searchable
  }
}

async function loadSites() {
  try {
    const r = await ds.callIndexerSafe('/v1/sites');
    const list = Array.isArray(r) ? r
              : (r && r.sites) ? r.sites
              : (r && r.items) ? r.items
              : [];
    if (!list.length) return;
    const knownDomains = new Set(
      ENTRIES.filter(e => e.kind === 'site').map(e => e.label)
    );
    for (const s of list) {
      if (knownDomains.has(_siteKey(s))) continue;
      pushSiteEntry(s);
    }
    _sitesLoaded = true;
  } catch (_) { /* soft fail */ }
}

let _primed = false;
let _tokenTimer = null;
let _siteTimer = null;

export async function primeIndex() {
  if (_primed) return;
  _primed = true;
  // First-time eager fetch.
  loadCustomTokens();
  loadSites();
  // Periodic auto-pull so newly-launched tokens / NFTs / sites
  // show up in the dropdown without a manual refresh.
  if (_tokenTimer) clearInterval(_tokenTimer);
  if (_siteTimer)  clearInterval(_siteTimer);
  _tokenTimer = setInterval(loadCustomTokens, TOKEN_REFRESH_MS);
  _siteTimer  = setInterval(loadSites,  SITE_REFRESH_MS);
}

// Stop the background loops (useful for tests; not called in prod).
export function stopAutoPull() {
  if (_tokenTimer) { clearInterval(_tokenTimer); _tokenTimer = null; }
  if (_siteTimer)  { clearInterval(_siteTimer);  _siteTimer  = null; }
  _primed = false;
}

// Manual refresh — wired to header's Refresh-on-click if we add
// one later. Returns the new entry count.
export async function refreshIndex() {
  await Promise.all([loadCustomTokens(), loadSites()]);
  return ENTRIES.length;
}

// Recognizers for direct chain identifiers. When the query matches
// one of these shapes we surface it as the FIRST result, ahead of
// any token/org guess. The dropdown still shows other matches below.
//
//   • 64-char hex      → /tx/<hash>  AND /block/<hash> (we offer both)
//   • all digits       → /block/<height>
//   • a name / @name   → /names/<name>
//   • Anything else    → standard text search
function buildDirectMatches(q) {
  const out = [];
  const lower = q.toLowerCase();
  if (/^[0-9a-f]{64}$/.test(lower)) {
    out.push({
      kind: 'tx', label: q, symbol: q,
      sub: 'transaction hash (32 bytes)',
      href: '#/tx/' + lower,
      iconGlyph: '🔗',
      badge: 'tx',
      haystack: lower,
    });
    out.push({
      kind: 'block', label: q, symbol: q,
      sub: 'or interpret as block hash',
      href: '#/block/' + lower,
      iconGlyph: '⬛',
      badge: 'block',
      haystack: lower,
    });
  } else if (/^\d{1,9}$/.test(q)) {
    out.push({
      kind: 'block', label: 'Block #' + Number(q).toLocaleString('en-US'), symbol: q,
      sub: 'jump to block height',
      href: '#/block/' + q,
      iconGlyph: '⬛',
      badge: 'block',
      haystack: lower,
    });
  }
  const name = chain.canonName(q);
  if (/^[a-z0-9_.-]{1,32}$/.test(name) && (q.trim().startsWith('@') || !/^\d+$/.test(name))) {
    out.push({
      kind: 'address', label: '@' + name, symbol: name,
      sub: 'look up this @name — owner, price, for sale',
      href: '#/names/' + encodeURIComponent(name),
      iconGlyph: '@',
      badge: 'name',
      haystack: name,
    });
  }
  return out;
}

// Lightweight prefix + substring match. Direct chain-identifier
// matches come FIRST, then prefix matches, then substring, then
// haystack. Verified entries get a small boost.
//
// We try BOTH the verbatim query (lowercased) and the tight
// normalized form (`_normalize`: strips spaces, dashes, dots,
// underscores). That way typing "ionswap" or "ion-swap" or "Ion
// Swap" all surface the same entries. Whichever variant gets a
// hit, the higher score wins.
export function searchLocal(query, limit = 12) {
  const q = (query || '').trim();
  if (!q) return [];

  const direct = buildDirectMatches(q);
  const ql = q.toLowerCase();
  const qt = _normalize(q);

  const scored = [];
  for (const e of ENTRIES) {
    const sym = (e.symbol || '').toLowerCase();
    const symTight = _normalize(e.symbol);
    const label = (e.label || '').toLowerCase();
    const labelTight = _normalize(e.label);
    let score = 0;
    // Exact / prefix wins on either form.
    if (sym === ql || symTight === qt)                       score = 100;
    else if (sym.startsWith(ql) || symTight.startsWith(qt))  score = 80;
    else if (label === ql || labelTight === qt)              score = 70;
    else if (label.startsWith(ql) || labelTight.startsWith(qt)) score = 60;
    else if (sym.includes(ql)   || symTight.includes(qt))    score = 50;
    else if (label.includes(ql) || labelTight.includes(qt))  score = 40;
    else if (e.haystack.includes(ql) ||
             (e.haystackTight || '').includes(qt))           score = 20;
    if (score > 0) {
      if (e.badge === 'verified') score += 3;
      scored.push({ score, entry: e });
    }
  }
  scored.sort((a, b) => b.score - a.score);
  return [...direct, ...scored.slice(0, Math.max(0, limit - direct.length)).map(s => s.entry)];
}

// Group entries by kind for the dropdown's sectioned layout.
// Direct chain-identifier suggestions (tx/block/address) come at
// the TOP under "Open directly" so the user sees the most relevant
// option first.
const KIND_LABELS = {
  tx:             'Open directly',
  block:          'Open directly',
  address:        'Open directly',
  token:          'Native assets',
  nft:            'NFTs',
  'custom-token': 'Launched tokens',
  org:            'Organizations',
  site:           'Sovereign sites',
};

export function groupByKind(entries) {
  const groups = new Map();
  // Combine tx + block + address into one 'Open directly' section.
  const directKinds = new Set(['tx', 'block', 'address']);
  for (const e of entries) {
    const key = directKinds.has(e.kind) ? '__direct' : e.kind;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(e);
  }
  const order = ['__direct', 'token', 'custom-token', 'nft', 'org', 'site'];
  const out = [];
  for (const k of order) {
    if (!groups.has(k)) continue;
    const label = k === '__direct' ? 'Open directly' : (KIND_LABELS[k] || k);
    out.push({ kind: k, label, entries: groups.get(k) });
  }
  return out;
}

export function initialsFor(label) { return initials(label); }
