// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// chain.js — every explorer read of chain data, from the reader's own node. What the directory holds is what its
// owners chose to publish (an asset's name and picture, a collection, a @name); none of it is a holder, a balance or a
// trade. Pages read the directory's apply-order log newest first by cursor, the refill door's own shape: each request
// returns at most 48 rows, and a page view makes at most `maxPages` requests; "load more" continues from the cursor.

import * as ds from './data-source.js';

export const KIND = Object.freeze({ NAME: 0, GROUP: 1, PROFILE: 2, NAME_TRANSFER: 3, COLLECTION: 4, ASSET: 5, ASSET_FILE: 6, ASSET_SUPPLY: 7 });
const PAGE = 48;
const US = '\u001f';
const IMAGE_MIME = /^image\/(png|jpeg|webp)$/;

// One page of the directory log: { total, from, entries:[{i, kind, key, address, name, topic, pic}] }.
export async function dirLogPage(from, max = PAGE) {
  const r = await ds.nodeGet('/dir/log', { from, max });
  if (!r || r.status !== 'OK') throw new Error((r && (r.error || r.detail)) || 'the node did not serve its directory log');
  return r;
}

// Walk the log newest first, keeping entries `keep` accepts, until `want` are found or `maxPages` requests are made.
// Returns { items, cursor } — pass `cursor` back to continue (null once the log's start is reached).
export async function scanNewest(keep, want, cursor = null, maxPages = 4) {
  let end = cursor;
  if (end == null) end = (await dirLogPage(0, 1)).total;
  const items = [];
  let pages = 0;
  while (end > 0 && items.length < want && pages < maxPages) {
    const from = Math.max(0, end - PAGE);
    const page = await dirLogPage(from, end - from);
    for (const e of (page.entries || []).slice().reverse()) if (keep(e)) items.push(e);
    end = from;
    pages++;
  }
  return { items, cursor: end > 0 ? end : null };
}

// An asset entry's `name` is `kind ␟ symbol ␟ name ␟ logo digest`.
export function parseAssetEntry(e) {
  const [kind, symbol, name, logo] = String(e.name || '').split(US);
  return { id: e.key, kind: kind === 'nft' ? 'nft' : 'token', symbol: symbol || '', name: name || '', logo: logo || '', creator: e.address || '', hasPic: !!e.pic };
}

export async function recentAssets(kind, want = 24, cursor = null) {
  const r = await scanNewest(e => e.kind === KIND.ASSET && parseAssetEntry(e).kind === kind, want, cursor);
  return { items: r.items.map(parseAssetEntry), cursor: r.cursor };
}

// Names newest first, each once (a later hand-over of the same name is the same name).
export async function recentNames(want = 36, cursor = null) {
  const seen = new Set();
  const r = await scanNewest(e => {
    if (e.kind !== KIND.NAME && e.kind !== KIND.NAME_TRANSFER) return false;
    if (seen.has(e.key)) return false;
    seen.add(e.key);
    return true;
  }, want, cursor);
  return { items: r.items.map(e => ({ name: e.key, handedOver: e.kind === KIND.NAME_TRANSFER })), cursor: r.cursor };
}

export async function asset(id) {
  const r = await ds.nodeGet('/dir/asset', { id });
  return r && r.found ? r : null;
}

const _art = new Map();
// An asset's picture as a data: URL (the chain keeps the bytes by digest), or '' when the chain holds none.
export function assetArt(id) {
  if (!_art.has(id)) {
    _art.set(id, ds.nodeGet('/dir/asset_art', { id }).then(r => (r && r.found ? hexToDataUrl(r.mime, r.art_hex) : ''), () => ''));
  }
  return _art.get(id);
}

export async function collections(skip = 0, max = PAGE) {
  const r = await ds.nodeGet('/dir/collections', { skip, max });
  return { total: Number(r.total || 0), items: r.collections || [] };
}

export async function collection(handle, from = 0) {
  const r = await ds.nodeGet('/dir/collection', { handle, from, max: PAGE, cover: true });
  return r && r.found ? r : null;
}

export async function pools(q = '', skip = 0) {
  const r = await ds.nodeGet('/ion/pools', { q, skip, max: PAGE });
  return { ready: r.ready !== false, total: Number(r.total || 0), items: r.pools || [] };
}

// `@name` → its current on-chain address (null when nobody holds it).
export async function resolveName(name) {
  const r = await ds.nodeGet('/dir/resolve', { name: canonName(name) });
  return r && r.status === 'OK' ? (r.address || null) : null;
}

// The node's own canonical form (`directory::canon_name`): trim, drop one leading @, trim, lower-case.
export function canonName(s) {
  return String(s || '').trim().replace(/^@/, '').trim().toLowerCase();
}

export function hexToDataUrl(mime, hex) {
  if (!hex || !IMAGE_MIME.exec(mime || '')) return '';
  let bin = '';
  for (let i = 0; i < hex.length; i += 2) bin += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  return 'data:' + mime + ';base64,' + btoa(bin);
}
