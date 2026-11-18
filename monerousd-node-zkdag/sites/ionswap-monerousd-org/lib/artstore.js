// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// lib/artstore.js — the pictures of the NFTs and tokens this person made or was handed, kept on this device.
//
// An asset's picture is not on the chain (node state does not grow): the chain binds the picture's digest into the
// asset, and the picture travels in the asset's CARD. A card with a picture is too large for the wallet's own name
// store, so this app keeps those cards here, by the asset's tag. Every card kept here was first read by the wallet,
// which refuses a picture that is not the asset's own, so a picture shown from this store is always the right one.
//
// LOCAL-STORAGE-REQUIRED: a created asset's picture is in no proof, record or wire field a wallet can read back (the
//   chain keeps only its 32-byte digest); it reaches a device only as a card a person hands it or makes. Losing this
//   store loses pictures and names on this device, never an NFT: a card is rebuilt from the picture file, or handed
//   over again.
// bound: at most KEPT cards of at most 100 KB each (the wallet's card limit), the oldest-used dropped past that:
//   about 50 MB at the very most, in this app's own storage on this device. Never a term in blocks, notes or height.
const DB = 'ionswap-art', STORE = 'cards', KEPT = 500;
const memory = new Map(); // used when this device gives the app no storage (a private window)

function open() {
  return new Promise((ok) => {
    try {
      const rq = indexedDB.open(DB, 1);
      rq.onupgradeneeded = () => rq.result.createObjectStore(STORE, { keyPath: 'tag' });
      rq.onsuccess = () => ok(rq.result);
      rq.onerror = () => ok(null);
      rq.onblocked = () => ok(null);
    } catch (_) { ok(null); }
  });
}
const done = (rq) => new Promise((ok) => { rq.onsuccess = () => ok(rq.result); rq.onerror = () => ok(null); });

// Keep a card under its tag: { tag, card, symbol, name, kind, art_hex, art_mime }.
export async function keep(entry) {
  const row = { ...entry, tag: String(entry.tag).toLowerCase(), used: Date.now() };
  memory.set(row.tag, row);
  const db = await open();
  if (!db) return;
  const st = db.transaction(STORE, 'readwrite').objectStore(STORE);
  await done(st.put(row));
  const all = (await done(st.getAll())) || [];
  if (all.length > KEPT) for (const old of all.sort((a, b) => a.used - b.used).slice(0, all.length - KEPT)) st.delete(old.tag);
}
export async function all() {
  const db = await open();
  const rows = db ? (await done(db.transaction(STORE).objectStore(STORE).getAll())) || [] : [];
  for (const r of rows) memory.set(r.tag, r);
  return Array.from(memory.values());
}
export async function get(tag) {
  const t = String(tag).toLowerCase();
  if (memory.has(t)) return memory.get(t);
  const db = await open();
  const row = db ? await done(db.transaction(STORE).objectStore(STORE).get(t)) : null;
  if (row) memory.set(t, row);
  return row || null;
}
// A picture as something an <img> can show.
export function pictureUrl(entry) {
  if (!entry || !entry.art_hex) return null;
  const bytes = new Uint8Array((String(entry.art_hex).match(/.{2}/g) || []).map((x) => parseInt(x, 16)));
  return URL.createObjectURL(new Blob([bytes], { type: entry.art_mime || 'image/webp' }));
}
