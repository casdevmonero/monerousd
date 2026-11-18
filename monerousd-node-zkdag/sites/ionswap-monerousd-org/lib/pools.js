// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// lib/pools.js — what the pools page asks the connected wallet, and the arithmetic it shows a person BEFORE they act.
// A pool here is made by people: anyone adds liquidity and takes its own out again whenever it wants. The chain keeps
// each pool's two balances, its share count and its price (one price for every order of a pool that lands in the same
// block); it never keeps who placed an order or who provides. Every number a person acts on is recomputed by the
// chain: the figures below are estimates for the screen, labelled as such where they are shown.
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. Its second party is the wallet that frames it; that crossing is
// exercised with the real wallet and real nodes, never inside this file.
import { ask } from './native.js';

const READ = 25000;
const SLOW = 240000; // an order proves one or two spends in the wallet before it is sent

export const UNIT = 100000000n; // every token and USDm have 8 decimals
export const LOCKED_SHARES = 1000n; // the first deposit's locked minimum (a dust amount nobody can remove)
export const GRADUATION_USDM = 50000n * UNIT; // the USDm at which a launch curve becomes a pool
export const LAUNCH_BASE_USDM = 5000n * UNIT; // what a launch curve starts against: it sets the first price and is never paid out

// ── THE FEE A TRADE PAYS IS THE CHAIN'S, never this site's. Every pool read the wallet relays carries the schedule the chain's
// batch rule charges (the node's `fees`: a pool's split and a launch curve's) and each pool row its own (`fee`). The site
// keeps the schedule the chain reported last and states no rate of its own; before one has arrived, an estimate is '—'.
let FEES = null;
const splitOf = (f) =>
  f && f.total_bps !== undefined
    ? { pool: big(f.pool_bps), creator: big(f.creator_bps), protocol: big(f.protocol_bps), publisher: big(f.publisher_bps), total: big(f.total_bps) }
    : null;
const keepFees = (r) => {
  if (r && r.fees && r.fees.pool && r.fees.curve) FEES = { pool: splitOf(r.fees.pool), curve: splitOf(r.fees.curve) };
  return r;
};
/** The fee split a trade of `p` pays (its own row's, else the schedule's for `kind`), or null before the chain has said. */
export function feeOf(p, kind) {
  const own = p && splitOf(p.fee);
  if (own) return own;
  const k = kind || (p && p.kind) || 'pool';
  return FEES ? FEES[k === 'curve' ? 'curve' : 'pool'] : null;
}
/** Hundredths of a percent as a percent figure ("0.3", "0.05"), for the screen. */
export function pctOf(bps) {
  const b = big(bps);
  const whole = b / 100n, frac = String(b % 100n).padStart(2, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : String(whole);
}
// Every order pays the chain's flat network fee through a USDm spend. An order that brings no USDm for the pool (a sale,
// a removal, a launch) brings one atomic unit of it for that, so it needs this much USDm in the wallet: the fee and the unit.
export const NETWORK_FEE = 100000n; // 0.001 USDm
export const FEE_USDM_NEEDED = NETWORK_FEE + 1n;
export const needsFeeText = 'This needs about $0.001 of USDm in your wallet for the network fee, and your wallet holds less.';

// ── asks (the wallet reads its own node; no server is named and none learns which pool a person looks at)
export const list = (q, skip = 0, max = 50) => ask('ionPools', { q: String(q || ''), skip, max }, READ).then(keepFees);
/** One pool, and beside it what THIS wallet holds for it. The second read is the wallet's own notes, so the wallet
 *  answers it only when its user lets this site see balances; without that the pool still reads and `mine` is null. */
export async function pool(token) {
  const r = keepFees(await ask('ionPool', { token }, READ));
  try { r.mine = await ask('ionPosition', { token }, READ); } catch (e) { r.mine = null; r.mineWhy = e; }
  return r;
}
/** The pool orders the wallet sent since it was opened, newest first, each with what it has been paid so far (read
 *  from the wallet's own notes, so the wallet answers only when its user lets this site see balances). */
export const orders = () => ask('ionOrders', {}, READ);
export const add = (token, tokenAtomic, usdmAtomic) => ask('ionAdd', { token, tokenAtomic: String(tokenAtomic), usdmAtomic: String(usdmAtomic) }, SLOW);
export const remove = (token, shares) => ask('ionRemove', { token, shares: String(shares) }, SLOW);
// ── LIQUIDITY LOCKS (spec §14; user 2026-11-12). A lock is the provider's own choice: its shares come back locked until a
// Monday it picks, and nobody, the provider included, can take that liquidity out before that day. The chain enforces it
// at the one place a removal is decided; these asks only carry the person's choice to the wallet, which states the date
// in its own sheet before anything is spent.
export const lock = (token, shares, fromWeek, untilWeek) => ask('ionLock', { token, shares: String(shares), fromWeek, untilWeek }, SLOW);
export const unlock = (token, shares, week) => ask('ionUnlock', { token, shares: String(shares), week }, SLOW);
export const removeLocked = (token, shares, week) => ask('ionRemoveLocked', { token, shares: String(shares), week }, SLOW);
// The chain's grid of unlock dates: week w begins on Monday 00:00 UTC, week 0 on Monday 5 January 1970.
export const WEEK_ZERO_SECS = 345600;
export const WEEK_SECS = 604800;
export const LOCK_WEEKS_MAX = 208; // four years
export const weekStartMs = (w) => (WEEK_ZERO_SECS + w * WEEK_SECS) * 1000;
/** The first unlock week on or after a moment (ms): the Monday 00:00 UTC on or after it. */
export const weekOnOrAfter = (ms) => Math.ceil((ms / 1000 - WEEK_ZERO_SECS) / WEEK_SECS);
export const weekDate = (w) => new Date(weekStartMs(w)).toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
/** A pool's lock as the node read it: `{ locked, pct, first }` — locked when more than half of its shares cannot be taken
 *  out now (shares locked until a later Monday, plus the dust no provider holds); `pct` that part; `first` the earliest
 *  future unlock week's date, or null. A launch curve's liquidity can never be taken out: it reads locked, 100 %. */
export function lockState(p) {
  const l = (p && p.lock) || {};
  const pct = Number(l.pct_e2 || 0) / 100;
  const first = l.first_unlock_secs == null ? null : new Date(Number(l.first_unlock_secs) * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
  return { locked: l.status === 'locked', pct, first, nowWeek: Number.isFinite(Number(l.now_week)) ? Number(l.now_week) : null };
}
const PADLOCK = (open) => '<svg viewBox="0 0 16 16" width="13" height="13" aria-hidden="true" focusable="false"><rect x="2.5" y="7" width="11" height="8" rx="2" fill="currentColor"/><path d="' + (open ? 'M5 7V4.8a3 3 0 0 1 5.8-1.1' : 'M5 7V5a3 3 0 0 1 6 0v2') + '" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
/** ⭐ THE LOCK ICON a pool shows everywhere it is listed (user 2026-11-12: "A green locked liquidity icon should show up on
 *  locked pools, a orange unlocked liquidity icon should show up on unlocked pools"), always with the exact part locked,
 *  so a dust lock never reads as a locked pool. `long` adds the first unlock date. */
export function lockBadge(p, long) {
  const st = lockState(p);
  const curve = p && p.kind === 'curve';
  const pct = st.pct >= 99.995 ? '100' : st.pct >= 10 ? st.pct.toFixed(0) : st.pct.toFixed(st.pct < 1 ? 2 : 1);
  const words = curve ? 'liquidity locked for good' : st.pct > 0.005 ? pct + '\u00a0% locked' : 'unlocked';
  const tip = curve
    ? 'A launch curve\'s liquidity can never be taken out by anyone.'
    : (st.locked ? 'Locked: more than half of this pool\'s liquidity cannot be taken out before its unlock date.' : 'Unlocked: most of this pool\'s liquidity can be taken out by its providers at any time.') +
      ' ' + pct + ' % cannot be taken out now' + (st.first ? '; the next unlock is ' + st.first : '') + '.';
  return '<span class="lockchip ' + (st.locked || curve ? 'locked' : 'unlocked') + '" title="' + tip.replace(/"/g, '&quot;') + '">' + PADLOCK(!(st.locked || curve)) +
    '<span>' + words + (long && st.first && !curve ? ' · next unlock ' + st.first : '') + '</span></span>';
}
export const claim = (token) => ask('ionClaim', { token }, SLOW);
export const launch = (token, tokenAtomic) => ask('ionLaunch', { token, tokenAtomic: String(tokenAtomic) }, SLOW);
export const buy = (token, usdmAtomic, minOut) => ask('ionBuy', { token, usdmAtomic: String(usdmAtomic), minOut: String(minOut) }, SLOW);
export const sell = (token, tokenAtomic, minOut) => ask('ionSell', { token, tokenAtomic: String(tokenAtomic), minOut: String(minOut) }, SLOW);
/** One token for another in ONE order: `from` is sold in its pool and the chain itself spends that USDm in `to`'s pool.
 *  Two floors, both the person's: `minUsdm` (below it everything sold comes back) and `minOut` (below it the USDm
 *  arrives instead of the second token). */
export const swap = (from, to, tokenAtomic, minUsdm, minOut) => ask('ionSwap', { from, to, tokenAtomic: String(tokenAtomic), minUsdm: String(minUsdm), minOut: String(minOut) }, SLOW);

// ── reading a pool row (amounts arrive as decimal strings: they are wider than a JavaScript number)
export const big = (v) => { try { return BigInt(String(v ?? '0').split('.')[0] || '0'); } catch (_) { return 0n; } };
export const isToken = (s) => /^[0-9a-f]{64}$/i.test(String(s || ''));
export const label = (p) => (p && p.symbol ? p.symbol : p ? 'token ' + String(p.token).slice(0, 6) + '…' : '?');

/** Atomic units as a number of whole units, for the screen only (never for an order). */
export const whole = (atomic) => Number(big(atomic)) / 1e8;

/** A person's typed amount as atomic units, exactly (no floating point): "12.5" → 1250000000n. `null` when it is not an amount. */
export function atomic(text) {
  const t = String(text ?? '').trim().replace(/,/g, '');
  if (!/^\d*(\.\d{0,8})?$/.test(t) || t === '' || t === '.') return null;
  const [a, b = ''] = t.split('.');
  return BigInt(a || '0') * UNIT + BigInt((b + '00000000').slice(0, 8));
}

/** USDm for one whole token, as a number for the screen: the pool's own price (a curve prices against its starting base too). */
export function price(p) {
  if (!p || p.price_e12 == null) return null;
  return Number(p.price_e12) / 1e12;
}

/** A price ring `[[seconds, price × 10^12], …]` as chart points. */
export const points = (p) => ((p && p.prices) || []).map((e) => [Number(e[0]), Number(e[1]) / 1e12]);

// ── estimates shown before a person acts. The chain's own rule: every order of a pool that lands in one block gets ONE
// price, so the true figure depends on the other orders of that block. These assume the order is alone in its block,
// and the order itself carries a floor (the least the person accepts): below it the chain hands the whole order back.
const net = (amount, bps) => amount - ((amount * bps + 9999n) / 10000n);

/** Tokens a buy of `usdmIn` would get, or null while the chain has not said what the pool's fee is. */
export function buyEstimate(p, usdmIn) {
  const f = feeOf(p);
  if (!f || usdmIn == null) return null;
  const x = big(p.token_atomic);
  const y = big(p.usdm_atomic) + big(p.virtual_usdm_atomic);
  if (x <= 0n || y <= 0n || usdmIn <= 0n) return 0n;
  const dy = net(usdmIn, f.total);
  return (dy * x) / (y + dy);
}

/** USDm a sale of `tokenIn` would get, or null while the chain has not said what the pool's fee is. */
export function sellEstimate(p, tokenIn) {
  const f = feeOf(p);
  if (!f || tokenIn == null) return null;
  const x = big(p.token_atomic);
  const y = big(p.usdm_atomic) + big(p.virtual_usdm_atomic);
  if (x <= 0n || y <= 0n || tokenIn <= 0n) return 0n;
  const dx = net(tokenIn, f.total);
  const out = (dx * y) / (x + dx);
  // a curve never pays out the base it started against, only what buyers really put in
  const real = big(p.usdm_atomic);
  return p.kind === 'curve' && out > real ? real : out;
}

/** The floor an order states: the estimate less `slipBps` (the least the person accepts; below it the order is handed back whole). */
export const floorOf = (estimate, slipBps = 100n) => (estimate * (10000n - slipBps)) / 10000n;

/** The tokens that go with `usdmIn` at the pool's own ratio (an addition brings both, in the pool's proportion). */
export function matchingTokens(p, usdmIn) {
  const x = big(p.token_atomic), y = big(p.usdm_atomic);
  if (y <= 0n) return 0n;
  return (usdmIn * x + y - 1n) / y; // rounded up: what does not fit the ratio is handed back
}

/** The shares an addition of `usdmIn` (with its matching tokens) would get, and the part of the pool they are. */
export function sharesFor(p, usdmIn) {
  const y = big(p.usdm_atomic), s = big(p.shares);
  if (y <= 0n || s <= 0n) return { shares: 0n, part: 0 };
  const shares = (usdmIn * s) / y;
  return { shares, part: Number((shares * 1000000n) / (s + shares)) / 10000 };
}

/** What `shares` hand back: both assets, in the pool's proportion. */
export function removeEstimate(p, shares) {
  const x = big(p.token_atomic), y = big(p.usdm_atomic), s = big(p.shares);
  if (s <= 0n || shares <= 0n) return { token: 0n, usdm: 0n };
  return { token: (x * shares) / s, usdm: (y * shares) / s };
}

/** What a person's shares are worth in USDm, counting both sides at the pool's own price. */
export function positionUsdm(p, shares) {
  const out = removeEstimate(p, shares);
  return out.usdm * 2n;
}

/** How far a launch curve is from becoming a pool, 0 to 100. */
export const graduation = (p) => Math.min(100, Number((big(p.usdm_atomic) * 10000n) / GRADUATION_USDM) / 100);
