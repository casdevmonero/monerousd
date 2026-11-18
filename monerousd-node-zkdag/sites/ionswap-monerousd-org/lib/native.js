// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// lib/native.js — what the native-swap pages share (2026-11-10).
//
// A NATIVE SWAP IS THE COINS THEMSELVES: Bitcoin in, Monero out (or the reverse, or to and from MoneroUSD) through the
// one bridge. Nothing is wrapped. These pages never hold a key, build a proof or decide a price: they ask the
// MoneroUSD wallet that frames them (`window.monerousd`, lib/wallet-bridge.js), and the wallet prices the swap, asks
// the user in ITS OWN sheet (every cost in dollars, drawn above this page) and acts through the same commands its own
// Buy / Sell page uses.
//
// AUTO-OPSEC is the wallet's one privacy setting, on by default. These pages show it and can ask the wallet to switch
// it; switching it off is answered by the wallet's own warning, never by a page.

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const usd = (v) => (v == null || !isFinite(v) ? '—' : '$' + Number(v).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }));
export const coinAmt = (v, d = 8) => (v == null || !isFinite(v) ? '—' : Number(v).toLocaleString('en-US', { maximumFractionDigits: d }));
export const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

// What an outside observer of each coin's OWN chain can see.
export const CHAIN_WORDS = { public: 'public chain', shielded: 'shielded chain', private: 'private, in your wallet' };

export const S = {
  wallet: false,
  // until the wallet answers: the coins the bridge holds, with no price (a price is the chain's, read by the wallet's node)
  assets: [
    { sym: 'BTC', name: 'Bitcoin', chain: 'public', usd: null },
    { sym: 'XMR', name: 'Monero', chain: 'shielded', usd: null },
    { sym: 'USDm', name: 'MoneroUSD', chain: 'private', usd: 1 },
    { sym: 'SAT', name: 'SAT', chain: 'private', usd: null },
  ],
  routes: null,
  opsec: true,
  from: 'BTC',
  to: 'XMR',
  amount: '',
  dest: 'vault', // Bitcoin only: this wallet's own vault, or an address
  addr: '',
  busy: false,
  last: null, // what the wallet answered to the last swap
  err: '',
};

export const asset = (sym) => S.assets.find((a) => a.sym === sym) || { sym, name: sym, chain: 'private', usd: null };

export function routeOf(from, to) {
  if (S.routes) return S.routes.find((r) => r.from === from && r.to === to) || null;
  const coin = (s) => s === 'BTC' || s === 'XMR';
  if (coin(from) && coin(to) && from !== to) return { kind: 'coin', fee_pct: 0.2 };
  if (coin(from) && to === 'USDm') return { kind: 'add', fee_pct: 0.1 };
  if (from === 'USDm' && coin(to)) return { kind: 'cashout', fee_pct: 0.1 };
  if ((coin(from) && to === 'SAT') || (from === 'SAT' && coin(to))) return { kind: 'wallet', fee_pct: null };
  return null;
}

export const provider = () => (window.monerousd && window.monerousd.__walletBridge && typeof window.monerousd.rpc === 'function' ? window.monerousd : null);

// `waitMs`: a read answers in moments; a call the user confirms in the wallet's sheet waits for the user.
export async function ask(method, params, waitMs) {
  const p = provider();
  if (!p) throw new Error('Connect your wallet first: press Connect wallet at the top of the page.');
  return p.rpc(method, params || {}, waitMs);
}

// The wallet stopped answering this page (disconnected, or its link window was closed): pages go back to what a
// visitor with no wallet sees.
export function walletGone() {
  S.wallet = false;
  for (const fn of listeners) { try { fn(); } catch (_) { /* a page that is gone */ } }
}
// What a page shows where the person's wallet is needed: the sentence and a button that connects it, on this page.
export const connectNote = (to) => '<div class="note connect-note"><span>Connect your wallet ' + esc(to) + '.</span> <button type="button" class="btn primary" data-connect>Connect wallet</button></div>';
// What a page shows where the person has not let this site see their balances: the sentence and a button that asks.
export const hiddenNote = (what) => '<div class="note connect-note"><span>Your ' + esc(what) + ' are hidden from this site.</span> <button type="button" class="btn" data-connect-balances>Show them here</button></div>';
export const isHidden = (e) => !!(e && (e.hidden || /^HIDDEN:/.test(String(e.message || e))));
// What a page shows when a read of the person's own figures fails: the Show button when they are hidden from this
// site, the wallet's own words otherwise.
export const privateNote = (e, what) => (isHidden(e) ? hiddenNote(what) : '<div class="note bad">' + esc(String((e && e.message) || e)) + '</div>');

const listeners = new Set();
export const onLearned = (fn) => { listeners.add(fn); return () => listeners.delete(fn); };

// ── THE PRICE IS THE CHAIN'S OWN (2026-11-10) ────────────────────────────────────────────────────────────────────────
// A coin's dollar price on these pages is the chain's PRICE MARK and nothing else: each bonded validator samples the
// onion price relays by itself, signs what it saw, and the bond-weighted median of two thirds of bond is carried in a
// block (the node's `price_mark_tx`). It is the same number a deposit is minted at. No company feed, no number typed by
// a person, none shipped inside this app. Where it is read from:
//   * inside the wallet: the wallet reads its own node (`nativeAssets`);
//   * opened from any node with no wallet: that node's `/api/price-marks`, the same marks;
//   * on the public web with no node behind the page: there is no price to show, and the page says so.
// `PRICE.why` holds the plain reason when a coin has no price, so a missing price is never a silent dash.
export const PRICE = { from: '', read_at: 0, why: '' };
const PRICE_READ_MS = 60000; // a mark changes once a price epoch (ten minutes at the chain's target); a minute keeps the page within one
const sameAssets = (a, b) => JSON.stringify(a) === JSON.stringify(b);

async function nodePrices() {
  const r = await fetch('/api/price-marks', { cache: 'no-store' });
  // Only the node's LIVE word is a price. This page's offline layer (js/offline-cache.js) answers a failed read from
  // the last copy it kept, or from a shipped file, and says so in this header: an old price shown as the chain's own
  // is worse than no price (found 2026-11-10, before the site was deployed to a host with no node behind it).
  if (!r.ok || r.headers.get('X-Sov-Source')) throw new Error('no node behind this page');
  const j = await r.json();
  if (!j || !Array.isArray(j.prices)) throw new Error('no node behind this page');
  return j.prices;
}

// Ask what is traded and at what prices. Safe to call any number of times; pages are redrawn only when an answer changed.
export async function learn() {
  const before = JSON.stringify([S.assets, S.routes, S.opsec, S.wallet, S.err, PRICE.why]);
  if (provider()) {
    try {
      const r = await ask('nativeAssets');
      if (r && Array.isArray(r.assets)) S.assets = r.assets;
      if (r && Array.isArray(r.routes)) S.routes = r.routes;
      S.opsec = !(r && r.auto_opsec === false);
      S.wallet = true;
      S.err = '';
      PRICE.from = 'wallet'; PRICE.read_at = Date.now();
      PRICE.why = S.assets.some((a) => a.sym !== 'USDm' && a.sym !== 'SAT' && !a.usd) ? 'The chain has not published a price for every coin yet. Its validators publish one when two thirds of them agree.' : '';
    } catch (e) {
      S.err = String((e && e.message) || e);
    }
  } else {
    try {
      const marks = await nodePrices();
      // a coin the chain has NOT priced in this answer shows no price: a figure kept from an earlier answer would be
      // shown as if it were the chain's word now (found 2026-11-10: the old price stayed on screen)
      const next = S.assets.map((a) => {
        const m = marks.find((x) => x.asset === a.sym);
        if (m && m.usd > 0) return Object.assign({}, a, { usd: Number(m.usd), price_epoch: m.epoch, price_source: 'chain price mark' });
        return a.price_source === 'chain price mark' ? Object.assign({}, a, { usd: 0, price_epoch: undefined, price_source: '' }) : a;
      });
      if (!sameAssets(next, S.assets)) S.assets = next;
      PRICE.from = 'node'; PRICE.read_at = Date.now();
      PRICE.why = marks.length ? '' : 'The chain has not published a price yet. Its validators publish one when two thirds of them agree.';
    } catch (_) {
      PRICE.from = ''; PRICE.why = 'Prices come from the chain itself. Connect your wallet to read them through its node.';
    }
  }
  if (before !== JSON.stringify([S.assets, S.routes, S.opsec, S.wallet, S.err, PRICE.why])) {
    for (const fn of listeners) { try { fn(); } catch (_) { /* a page that is gone */ } }
  }
  return S.wallet;
}
window.addEventListener('monerousd#initialized', learn);

// Read the chain's price again while the page is open and in view (never while it is hidden).
function pollPrices() {
  if (!document.hidden) learn();
  setTimeout(pollPrices, PRICE_READ_MS);
}
setTimeout(pollPrices, PRICE_READ_MS);

// One line that says what a coin costs and where the number came from; '' for MoneroUSD, which is the dollar.
export function priceLine(a) {
  if (a.sym === 'USDm') return '';
  if (!a.usd && !PRICE.from) return ''; // no node behind the page: `PRICE.why` says so once, and no coin is called unpriced
  if (!a.usd) return a.sym === 'SAT' ? 'SAT is priced by its own batches, in Bitcoin or Monero' : 'No ' + a.name + ' price on the chain yet';
  return '1 ' + a.sym + ' = ' + usd(a.usd) + (a.price_epoch != null ? ' · chain price, epoch ' + a.price_epoch : a.price_source ? ' · ' + a.price_source : '');
}

// A coin's OWN mark is the file this app ships, and that file IS the chain software's one copy: every node compiles
// these same files in (`sovereign.rs` reads `sites/ionswap-monerousd-org/assets/…`) and serves them to the wallet and
// the explorer at /api/token-logo/<SYM>. So this app draws its own copy and asks no route for it. MEASURED 2026-11-12
// why it no longer asks the route first: on a host with no node behind the page (the public web) that request fails
// for every logo every time one is drawn, and the logo appeared only after the failure: a blank circle, then the mark,
// on every repaint. A coin with no mark gets a lettered chip, never another coin's logo.
const COIN_MARKS = { BTC: 'assets/coins/BTC.svg', XMR: 'assets/coins/XMR.svg', ETH: 'assets/coins/ETH.svg', ZEC: 'assets/coins/ZEC.svg', SOL: 'assets/coins/SOL.svg', USDm: 'assets/coins/USDm.svg', SAT: 'assets/sat-logo.png' };
export const coinDot = (sym) => (COIN_MARKS[sym]
  ? '<span class="coin logo"><img alt="' + esc(sym) + '" src="' + COIN_MARKS[sym] + '" /></span>'
  : '<span class="coin ' + esc(sym) + '">' + esc(String(sym).slice(0, 1)) + '</span>');
