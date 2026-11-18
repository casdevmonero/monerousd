// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// lib/dex.js — what the token, NFT and pool pages share (2026-11-10).
//
// HOW TRADING WORKS ON THIS CHAIN. There is no pooled contract holding everyone's tokens. A seller RESTS AN ORDER: an
// authorisation over a note that stays in the seller's own wallet, offering one lot at one price. A buyer FILLS it, and
// the chain settles both sides in one transaction. An order nobody filled never touches the chain, and the chain never
// shows who made or took one. (Pools, where anyone adds liquidity and takes its own out, are specified in
// docs/IONSWAP-POOLS-SPEC-20261110.md and are not on the chain yet; nothing here pretends otherwise.)
//
// These pages hold no key and build no proof. Every action is asked of the MoneroUSD wallet that frames the page
// (`window.monerousd`, lib/wallet-bridge.js); the wallet shows the cost in dollars in its own sheet and acts.
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. Its second party is the wallet that frames it; that crossing is
// exercised with the real wallet and real nodes (scratchpad/net/dex.py), never inside this file.
import { ask, esc, coinDot } from './native.js';

export const USDM = '0'.repeat(48);
export const UNIT = 100000000; // every token has 8 decimals; an NFT is ONE atomic unit
const SLOW = 180000; // a call the user confirms in the wallet's sheet waits for the user and for the proof
const READ = 25000;

export const isTag = (s) => /^[0-9a-f]{48}$/i.test(String(s || ''));
export const short = (tag) => String(tag || '').slice(0, 6) + '…' + String(tag || '').slice(-4);

// ── what the wallet holds and can name ──────────────────────────────────────────────────────────────────────
// Each entry: { tag, atomic, symbol, name, kind: 'coin' | 'token' | 'nft' | 'unknown', card }.
export async function holdings() {
  const r = await ask('assets', {}, READ);
  return (r && Array.isArray(r.assets) ? r.assets : []).map((a) => ({ ...a, tag: String(a.tag).toLowerCase(), atomic: Number(a.atomic) || 0 }));
}
export const find = (list, tag) => list.find((a) => a.tag === String(tag).toLowerCase()) || null;
export const label = (a) => (a && a.symbol ? a.symbol : a ? 'asset ' + String(a.tag).slice(0, 6) + '…' : '?');
export const amountText = (a, atomic) => (a && a.kind === 'nft' ? (Number(atomic) >= 1 ? '1 (the only one)' : '0') : (Number(atomic) / UNIT).toLocaleString('en-US', { maximumFractionDigits: 8 }));

// A card is the line an asset's creator shares. The wallet recomputes the asset's tag from the card's own facts, so a
// name is only ever shown under the tag it truly belongs to. Returns { tag, symbol, name, kind, card }.
export const addCard = (card) => ask('assetCard', { card: String(card || '').trim() }, READ);

// ── creating ────────────────────────────────────────────────────────────────────────────────────────────────
// The chain's price for creating one asset of this kind ('token' or 'nft'), read from the wallet's own node.
// `artBytes`: the size of the picture the creation puts on the chain; the answer's `fee_atomic` includes its kilobytes,
// and it also states `picture_kb_fee_atomic` (one kilobyte's price) and `art_max_bytes` (the largest picture kept).
export const createFee = (symbol, kind = 'token', artBytes = 0) => ask('createFee', { symbol, kind, artBytes }, READ);
export const create = (p) => ask('createToken', p, SLOW);
export const send = (asset, to, atomic) => ask('sendAsset', { asset, to, atomic }, SLOW);

// ── the book ────────────────────────────────────────────────────────────────────────────────────────────────
// `buy` is the asset received, `pay` the asset spent; `budget` is in atomic units of `pay`. The whole lattice (64 price
// levels) is read: an NFT priced at a few dollars rests far above the levels a cheap token uses.
const ALL = { fromLevel: 0, span: 64 };
export const quote = (buy, pay, budget) => ask('swapQuote', { assetA: buy, assetB: pay, budget: Math.floor(budget), ...ALL }, READ);
export const fill = (buy, pay, budget, minOut) => ask('swapExecute', { assetA: buy, assetB: pay, budget: Math.floor(budget), minOut: Math.floor(minOut), ...ALL }, SLOW);
export const depth = (give, get) => ask('bookDepth', { assetA: give, assetB: get, ...ALL }, READ);

export async function height() {
  const r = await ask('getHeight', {}, READ);
  const i = (r && r.info) || r || {};
  return Number(i.height != null ? i.height : i.blue_score != null ? i.blue_score : i.count) || 0;
}
// How long a resting order stays open, in blocks. The wallet rounds it up to the chain's public expiry grid, so an
// order carries no distinctive term.
export const OPEN_FOR_BLOCKS = 40000;

// Rest ONE order: give exactly `lot` of `give`, to be paid `pay` of `get`. The wallet rounds both down onto the chain's
// public grid (at most a tenth of a percent). The order needs a note of EXACTLY the lot: see `setAside`.
export async function rest(give, get, lot, pay) {
  const h = await height();
  return ask('orderPost', { give, get, lot: Math.floor(lot), pay: Math.floor(pay), expires: h + OPEN_FOR_BLOCKS }, SLOW);
}
// Cut a note of exactly `lot` by sending it to this wallet's own address (the order then rests on that note). Sending
// that same note to yourself again later is how an order is withdrawn: nobody can refuse or delay it.
export async function setAside(asset, lot) {
  // `self`: the wallet fills in its own address, so this page is never told one
  return send(asset, 'self', Math.floor(lot));
}
export const NO_EXACT_NOTE = /no note of exactly this lot size/i;

// The chain's value grid, mirrored for DISPLAY only (the wallet snaps for real): a value keeps 11 significant bits.
export function onGrid(v) {
  v = Math.floor(Number(v) || 0);
  if (v <= 0) return 0;
  const bits = Math.floor(Math.log2(v)) + 1;
  if (bits <= 11) return v;
  const cut = 2 ** (bits - 11);
  return Math.floor(v / cut) * cut;
}

// ── small pieces of page ────────────────────────────────────────────────────────────────────────────────────
export const dot = (a) => {
  const s = label(a);
  const hue = a && a.tag ? parseInt(String(a.tag).slice(0, 6), 16) % 360 : 24;
  if (a && a.kind === 'coin' && (a.symbol === 'USDm' || a.symbol === 'SAT')) return coinDot(a.symbol);
  return '<span class="coin" style="background:radial-gradient(circle at 30% 25%, hsl(' + hue + ' 90% 72%), hsl(' + hue + ' 75% 48%) 60%, hsl(' + hue + ' 80% 22%))">' + esc(s.slice(0, 1).toUpperCase()) + '</span>';
};
export function copyButton(text, words) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'ghost';
  b.textContent = words || 'Copy';
  b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(text); b.textContent = 'Copied'; } catch (_) { b.textContent = 'Select the text and copy it'; }
    setTimeout(() => { b.textContent = words || 'Copy'; }, 1600);
  });
  return b;
}
// A price for ONE token: cents are too coarse for a token worth a fraction of one.
export const price = (v) => (v == null || !isFinite(v) ? '—' : v >= 1 ? '$' + v.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) : '$' + Number(v.toPrecision(4)).toLocaleString('en-US', { maximumFractionDigits: 10 }));
export const errText = (e) => {
  const m = String((e && e.message) || e || '');
  if (/USER_DECLINED/.test(m)) return 'You cancelled in the wallet. Nothing moved.';
  return m.replace(/^Error:\s*/, '');
};
export const params = () => new URLSearchParams((location.hash.split('?')[1] || ''));
