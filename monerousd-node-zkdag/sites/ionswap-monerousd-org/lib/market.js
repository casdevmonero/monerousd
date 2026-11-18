// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// lib/market.js — what the chain's own record says about assets and collections (2026-11-11).
//
// Every token, NFT and collection is recorded by the block that created it: the name, the symbol, the creator, the
// picture, the collection (the node's `directory`, kinds "asset" and "collection"). Every node keeps that record, so
// each read here goes to ONE node's own copy:
//   * a connected wallet's own node (the wallet forwards the four public directory reads and nothing else), or
//   * with no wallet, the node that serves this page (its site host answers the same four reads under /api/market/).
// On the public web with neither, there is nothing to read and the page says so and offers Connect.
// Nothing is asked of anyone else, so nobody learns what a person looks at or holds. These pages never decide a name
// or a picture: they show what the chain recorded.
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. Its second parties are the wallet that answers it and the node
// behind that wallet; those crossings are exercised with the real wallet and real nodes (scratchpad/net/market.py).
import { ask, provider } from './native.js';

const WAIT = 20000;
export const PAGE = 24; // one screen of tiles; the next range is asked for by position, never by reading from the start

// ONE read of the chain's directory: `route` is the node's own route name, `body` its fields.
async function read(route, body) {
  if (provider()) {
    const r = await ask('nodeRpc', { path: '/dir/' + route, body: JSON.stringify(body) }, WAIT);
    return typeof r === 'string' ? JSON.parse(r) : r;
  }
  const r = await fetch('/api/market/' + route, { method: 'POST', cache: 'no-store', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  // this page's offline layer answers a failed read from an old copy and says so in this header: an old record shown
  // as the chain's own word is worse than none
  if (!r.ok || r.headers.get('X-Sov-Source')) throw new Error('NO_NODE');
  return r.json();
}
/// Can this page read the chain's record at all right now? (A connected wallet, or a node behind the page.)
export async function reachable() {
  if (provider()) return true;
  try { await read('collections', { skip: 0, max: 1 }); return true; } catch (_) { return false; }
}

/// A page of collections, newest first: { total, skip, collections: [{ handle, title, text, owner, pieces, has_cover }] }.
export const collections = (skip = 0) => read('collections', { skip, max: PAGE });
/// One collection and a page of its pieces: { found, handle, title, text, owner, total, from, pieces: [asset id…], cover_hex?, cover_mime? }.
export const collection = (handle, from = 0, cover = false) => read('collection', { handle, from, max: PAGE, cover });
/// One asset's record by its id (64 hex) or by the tag its notes carry (48 hex):
/// { found, id, tag, kind, symbol, name, creator, logo, collection, has_art }.
export const asset = (idOrTag) => read('asset', isTag(idOrTag) ? { tag: String(idOrTag).toLowerCase() } : { id: String(idOrTag).toLowerCase() });

const hexBytes = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
};
const toDataUrl = (mime, hex) => {
  const b = hexBytes(hex);
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return 'data:' + mime + ';base64,' + btoa(s);
};
// pictures already read in this visit, by asset id or by 'c:' + handle (a picture never changes: it is bound by digest)
const seen = new Map();
/// An asset's own picture as the chain keeps it, as a URL an <img> can show; '' when the chain holds none for it.
export async function picture(id) {
  const k = String(id).toLowerCase();
  if (seen.has(k)) return seen.get(k);
  let url = '';
  try {
    const r = await read('asset_art', { id: k });
    if (r && r.found && /^image\/(png|jpeg|webp)$/.test(r.mime)) url = toDataUrl(r.mime, r.art_hex);
  } catch (_) { /* no picture to show */ }
  // only a picture that arrived is remembered: a node that joined lately may hold the record before the bytes, and the
  // next look should ask again
  if (url) seen.set(k, url);
  return url;
}
/// A collection's cover as a URL an <img> can show; '' when it has none.
export async function cover(handle) {
  const k = 'c:' + canonHandle(handle);
  if (seen.has(k)) return seen.get(k);
  let url = '';
  try {
    const r = await collection(handle, 0, true);
    if (r && r.found && r.cover_hex && /^image\/(png|jpeg|webp)$/.test(r.cover_mime)) url = toDataUrl(r.cover_mime, r.cover_hex);
  } catch (_) { /* no cover to show */ }
  if (url) seen.set(k, url);
  return url;
}

export const isId = (s) => /^[0-9a-f]{64}$/i.test(String(s || '').trim());
export const isTag = (s) => /^[0-9a-f]{48}$/i.test(String(s || '').trim());
/// A collection's handle as the chain keeps it: lower case, no leading @ or #, spaces as dashes, and only the
/// characters a handle may hold (a-z, 0-9, - and _), at most 32.
export const canonHandle = (s) => String(s || '').trim().replace(/^[@#]+/, '').toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9_-]/g, '').slice(0, 32);
