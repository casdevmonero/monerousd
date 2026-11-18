// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// pages/pools.js — THE POOLS PAGE (user 2026-11-11: "a full uniswap style pools page with a search bar that list the
// top pools by liquidity and allows you to search all the other pools … ionswap pools are different from the launch
// pools and are withdrawable. having users add liquidity thats not withdrawable is funds loss").
//
// TWO KINDS OF POOL, never mixed on this page:
//   1. POOLS PEOPLE MAKE (the list, the search, a pool's own view). Anyone adds liquidity and holds shares; the shares
//      are the provider's own private notes, and handing them back returns both assets whenever the provider wants,
//      asking nobody. The page's "Add liquidity" appears ONLY on a pool of this kind, and beside it, always, "Remove".
//      A token still on its launch curve takes no liquidity from anyone: there the page shows the curve and offers
//      buying and selling, never adding.
//      SWAP (a tab of every opened pool): this pool's token for any other token that has a pool, in ONE order. The
//      token is sold here and the chain itself spends that USDm in the other pool a block later; the person states a
//      floor for each leg and is never left with less than one of them.
//   2. THE COIN POOLS (SAT against Bitcoin and Monero), given to the chain at launch and held by no key. Nobody
//      deposits into them, so the page offers no button to: it only draws their price.
//
// WHAT IS READ: this wallet's own node (its copy of every pool's two balances, share count and price, which the chain
// publishes once a block). No server is asked which pool a person looks at. WHAT IS SENT: one order, built and proved
// in the wallet, shown in dollars first.
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. Its second party is the wallet that frames it; that crossing is
// exercised with the real wallet and real nodes, never inside this file.
import { S, learn, ask, esc, usd, coinAmt, coinDot, connectNote, privateNote } from '../lib/native.js';
import * as dex from '../lib/dex.js';
import * as pl from '../lib/pools.js';

const PAGE = 50; // pools a page of the list
const NEXT_READ_MS = 20000; // the gap between background reads of the open view (a pool changes once a block)

function spark(points, id) {
  const pts = (points || []).map((p) => [Number(p[0]), Number(p[1])]).filter((p) => isFinite(p[0]) && isFinite(p[1]));
  if (pts.length < 2) return '<div class="muted">The price line draws itself as blocks carry orders for this pool.</div>';
  const xs = pts.map((p) => p[0]), ys = pts.map((p) => p[1]);
  const x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = Math.min(...ys), y1 = Math.max(...ys);
  const X = (x) => ((x - x0) / Math.max(1, x1 - x0)) * 300, Y = (y) => 58 - ((y - y0) / Math.max(1e-18, y1 - y0)) * 52;
  const d = pts.map((p, i) => (i ? 'L' : 'M') + X(p[0]).toFixed(1) + ' ' + Y(p[1]).toFixed(1)).join(' ');
  return '<svg class="spark" viewBox="0 0 300 64" preserveAspectRatio="none" aria-hidden="true"><defs><linearGradient id="' + id + '" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ff8a3d"/><stop offset="1" stop-color="rgba(255,138,61,0)"/></linearGradient></defs>' +
    '<path class="a" fill="url(#' + id + ')" d="' + d + ' L300 64 L0 64 Z"/><path class="l" pathLength="1" d="' + d + '"/></svg>';
}

const money = (atomic) => usd(pl.whole(atomic));
const units = (atomic, d = 4) => coinAmt(pl.whole(atomic), d);
const priceText = (p) => { const v = pl.price(p); return v == null ? '—' : dex.price(v); };
const kindChip = (p) => (p.kind === 'curve' ? '<span class="chip live">launch curve</span>' : '<span class="chip done">pool</span>');

// ───────────────────────────────────────────────────────── the list

function row(p, rank) {
  return '<a class="item" href="#/pools?token=' + esc(p.token) + '" style="text-decoration:none;color:inherit">' +
    '<span class="muted num" style="min-width:2ch;text-align:right">' + rank + '</span>' +
    '<span class="t">' + esc(pl.label(p)) + ' · USDm</span>' +
    '<b class="num">' + esc(money(p.liquidity_usdm_atomic)) + '</b>' +
    // the kind sits on the second line, where a phone has room for it (in the title it was cut off at 375 px)
    '<span class="s">' + kindChip(p) + ' ' + pl.lockBadge(p) + ' ' + esc(p.name || 'no name on the chain') + ' · one ' + esc(pl.label(p)) + ' is ' + esc(priceText(p)) + '</span></a>';
}

function coinCards(r) {
  return ((r && r.pools) || []).map((p) => {
    if (p.error) return '<div class="card stack"><div class="row"><h2>SAT · ' + esc(p.coin) + '</h2><span class="chip">not readable</span></div><div class="note bad">' + esc(p.error) + '</div></div>';
    return '<div class="card stack"><div class="row"><h2 class="pair">' + coinDot('SAT') + coinDot(p.coin) + '<span>SAT · ' + esc(p.coin) + '</span></h2><span class="chip">no key holds it</span></div>' +
      spark(p.points, 'ionCoin' + esc(p.coin)) +
      '<div class="kv"><span>One SAT, last cleared</span><b>' + esc(coinAmt(p.price_coin_per_sat, 10)) + ' ' + esc(p.coin) + '</b>' +
      '<span>Who can add to it</span><b>nobody</b><span>Who can take from it</span><b>nobody</b></div>' +
      '<a class="ghost" href="#/swap" style="text-align:center;text-decoration:none">Swap coins against it</a></div>';
  }).join('');
}

async function listView(root) {
  root.innerHTML = '<div><div class="eyebrow">Pools</div><h1>Add liquidity. <em>Take it out whenever you want.</em></h1>' +
    '<p class="lead">Every pool here was made by people. You hold your part as shares in your own wallet, and handing them back returns both assets, at any time, asking nobody. You can also choose to lock your part until a date, to show you are staying: a green lock marks a pool whose liquidity is mostly locked, an orange one a pool whose providers can leave at any time.</p></div>' +
    '<div class="card stack"><input class="field" id="plQ" type="search" autocomplete="off" spellcheck="false" placeholder="Search pools: name, symbol or id" aria-label="Search every pool by a token\'s name, its symbol or its id">' +
    '<div class="row"><b id="plHead">Top pools by liquidity</b><span class="muted" id="plCount"></span></div>' +
    '<div class="list" id="plList"><div class="note">Reading your node…</div></div>' +
    '<button type="button" class="ghost" id="plMore" hidden>Show more</button></div>' +
    '<div class="card stack" id="plMinePos" hidden></div>' +
    '<div class="card stack" id="plOpen"></div>' +
    '<div><div class="eyebrow">Coin pools</div><p class="lead">These two were given to the chain at launch. No key holds them, nobody adds to them and nobody can take from them; coin swaps clear against them.</p></div>' +
    '<div class="two" id="plCoin"><div class="note">Reading your node…</div></div>';
  const list = root.querySelector('#plList'), more = root.querySelector('#plMore'), q = root.querySelector('#plQ');
  let shown = 0, query = '', turn = 0;
  const load = async (reset) => {
    const mine = ++turn;
    if (reset) { shown = 0; list.innerHTML = '<div class="note">Reading your node…</div>'; }
    try {
      const r = await pl.list(query, shown, PAGE);
      if (mine !== turn || !root.isConnected) return;
      if (!r.ready) {
        list.innerHTML = '<div class="note warn">Your node is still collecting the pools from the network. They appear here on their own; nothing is lost and nothing needs doing.</div>';
        more.hidden = true;
        return;
      }
      const rows = (r.pools || []).map((p, i) => row(p, shown + i + 1)).join('');
      if (reset) list.innerHTML = rows || '<div class="note">' + (query ? 'No pool matches “' + esc(query) + '”.' : 'No pool has been opened yet. Open the first one below.') + '</div>';
      else list.insertAdjacentHTML('beforeend', rows);
      shown += (r.pools || []).length;
      root.querySelector('#plHead').textContent = query ? 'Pools matching “' + query + '”' : 'Top pools by liquidity';
      root.querySelector('#plCount').textContent = r.total + (r.total === 1 ? ' pool' : ' pools');
      more.hidden = shown >= r.total;
    } catch (e) {
      if (mine === turn) list.innerHTML = '<div class="note bad">' + esc(dex.errText(e)) + '</div>';
    }
  };
  let typing = 0;
  q.addEventListener('input', () => { clearTimeout(typing); typing = setTimeout(() => { query = q.value.trim(); load(true); }, 250); });
  more.addEventListener('click', () => load(false));
  load(true);
  positionsCard(root.querySelector('#plMinePos'));
  openCard(root.querySelector('#plOpen'));
  ask('nativePools', {}, 25000).then((r) => { if (root.isConnected) root.querySelector('#plCoin').innerHTML = coinCards(r) || '<div class="note">Your node named no coin pools.</div>'; })
    .catch((e) => { if (root.isConnected) root.querySelector('#plCoin').innerHTML = '<div class="note bad">' + esc(dex.errText(e)) + '</div>'; });
}

/** "Your positions": the pools this wallet holds shares of (its own share notes, named by its own node), each with
 *  what the shares are worth now. Hidden when the wallet holds none, or when its user has not let this site see
 *  balances (the pools above read without that). */
async function positionsCard(box) {
  let held;
  try { held = (await dex.holdings()).filter((a) => a.kind === 'share' && a.pool && Number(a.atomic) > 0); } catch (_) { return; }
  if (!held.length || !box.isConnected) return;
  // one row a pool: its plain shares and its locked shares (spec §14) are notes of different tags of the same pool
  const pools = new Map();
  for (const a of held) {
    const e = pools.get(a.pool) || { pool: a.pool, symbol: '', plain: 0n, locked: 0n, first: 0 };
    e.symbol = e.symbol || String(a.symbol || '').replace(/ \(locked\)$/, '');
    if (Number(a.lock_week) > 0) { e.locked += pl.big(a.atomic); e.first = e.first ? Math.min(e.first, Number(a.lock_week)) : Number(a.lock_week); } else e.plain += pl.big(a.atomic);
    pools.set(a.pool, e);
  }
  const rows = Array.from(pools.values());
  box.hidden = false;
  box.innerHTML = '<div class="row"><h2>Your positions</h2><span class="muted">' + rows.length + (rows.length === 1 ? ' pool' : ' pools') + '</span></div>' +
    '<div class="list" id="plPosList">' + rows.map((e) => '<a class="item" data-pool="' + esc(e.pool) + '" href="#/pools?token=' + esc(e.pool) + '" style="text-decoration:none;color:inherit">' + dex.dot({ symbol: e.symbol }) +
      '<span class="t">' + esc(e.symbol || 'pool shares') + '</span><b class="num" data-v>…</b><span class="s" data-s>Reading the pool…</span></a>').join('') + '</div>';
  // each position's worth is its part of the pool as the pool stands now (one read a position, through the wallet's node)
  for (const e of rows) {
    try {
      const r = await ask('ionPool', { token: e.pool }, 25000);
      const el = box.querySelector('[data-pool="' + e.pool + '"]');
      if (!el || !r || !r.found) continue;
      const shares = e.plain + e.locked, total = pl.big(r.pool.shares);
      const part = total > 0n ? Number((shares * 1000000n) / total) / 10000 : 0;
      const out = pl.removeEstimate(r.pool, e.plain);
      el.querySelector('[data-v]').textContent = money(pl.positionUsdm(r.pool, shares));
      el.querySelector('[data-s]').innerHTML = esc(part.toFixed(part < 1 ? 4 : 2) + ' % of the pool') +
        (e.plain > 0n ? esc(' · about ' + units(out.token) + ' ' + pl.label(r.pool) + ' and ' + money(out.usdm) + ' if you took out your unlocked part now') : '') +
        (e.locked > 0n ? ' <span class="lockchip locked">' + esc(money(pl.positionUsdm(r.pool, e.locked)) + ' locked · first unlock ' + pl.weekDate(e.first)) + '</span>' : '');
    } catch (_) { /* this row keeps its placeholder; the pool's own page still reads */ }
  }
}

/** "Open a pool": one of the tokens this wallet holds, by its id. */
async function openCard(box) {
  box.innerHTML = '<div class="row"><h2>Open a pool for a token you hold</h2></div>' +
    '<p class="muted">A token has one pool against USDm. The first deposit sets its price; every later one joins at the pool\'s own price.</p>' +
    '<div id="plMine" class="list"><div class="note">Reading your wallet…</div></div>';
  try {
    const held = (await dex.holdings()).filter((a) => a.kind !== 'nft' && a.id && Number(a.atomic) > 0);
    box.querySelector('#plMine').innerHTML = held.map((a) => '<a class="item" href="#/pools?token=' + esc(a.id) + '" style="text-decoration:none;color:inherit">' + dex.dot(a) +
      '<span class="t">' + esc(dex.label(a)) + '</span><b class="num">' + esc(dex.amountText(a, a.atomic)) + '</b><span class="s">Open its pool, or add to it</span></a>').join('') ||
      '<div class="note">Your wallet holds no token yet. <a href="#/create">Launch one</a>, or buy one on the <a href="#/tokens">tokens page</a>.</div>';
  } catch (e) {
    box.querySelector('#plMine').innerHTML = '<div class="note bad">' + esc(dex.errText(e)) + '</div>';
  }
}

// ───────────────────────────────────────────────────────── one pool

function facts(p, mine) {
  const share = pl.big(mine && mine.shares), total = pl.big(p.shares);
  const part = total > 0n ? Number((share * 1000000n) / total) / 10000 : 0;
  return '<div class="facts"><div class="fact"><b>' + esc(money(p.liquidity_usdm_atomic)) + '</b><span>liquidity</span></div>' +
    '<div class="fact"><b>' + esc(priceText(p)) + '</b><span>one ' + esc(pl.label(p)) + '</span></div>' +
    '<div class="fact"><b>' + (share > 0n ? esc(money(pl.positionUsdm(p, share))) : '—') + '</b><span>' + (share > 0n ? 'yours (' + part.toFixed(part < 1 ? 4 : 2) + ' % of the pool)' : 'you hold no part of it') + '</span></div></div>' +
    '<div class="kv"><span>In the pool</span><b>' + esc(units(p.token_atomic)) + ' ' + esc(pl.label(p)) + ' and ' + esc(money(p.usdm_atomic)) + '</b>' +
    (p.kind === 'pool' ? '<span>Who can take liquidity out</span><b>each provider, its own part: at any time, or from the date it chose to lock it until</b><span>Liquidity lock</span><b>' + pl.lockBadge(p, true) + '</b>' : '<span>Becomes a pool at</span><b>' + esc(money(pl.GRADUATION_USDM)) + ' bought (' + pl.graduation(p).toFixed(1) + ' % there)</b>') + '</div>';
}

// ONE ORDER SPENDS ONE NOTE of each asset it brings. A balance can sit in several notes (every payment received is its
// own note), so beside what the wallet holds the page reads the LARGEST single note of each asset and says what fits
// in one order BEFORE the wallet proves anything. (A wallet that does not say the largest note is read as holding one.)
const largestNote = (mine) => ({ t: pl.big(mine.token_note_max ?? mine.token), u: pl.big(mine.usdm_note_max ?? mine.usdm) });
const splitNote = (most) => 'Your wallet holds this in several notes, and one order spends one note: the most you can use in one order now is ' + most + '. To use more, first send the amount to your own address (it arrives as one note).';
// what a USDm leg needs in its one note: the amount and the network fee
const usdmFits = (mine, u) => u + pl.NETWORK_FEE <= largestNote(mine).u;
const usdmMost = (mine) => { const m = largestNote(mine).u - pl.NETWORK_FEE; return money(m > 0n ? m : 0n); };
// why a USDm amount does not fit: the fee does not fit beside it, or the balance is split across notes
const usdmWhy = (mine, u) => (u + pl.NETWORK_FEE > pl.big(mine.usdm)
  ? 'This needs ' + money(u) + ' and the network fee of about $0.001, and your wallet holds ' + money(pl.big(mine.usdm)) + '.'
  : splitNote(usdmMost(mine)));

function said(box, kind, text) { box.innerHTML = '<div class="note ' + kind + '">' + text + '</div>'; }
const ACCEPTED = 'Order accepted. A block carries it and the next one pays it: what you receive arrives in your wallet on its own, usually within a minute.';

/** One form of the pool view. `build()` reads the fields and returns `{ line, go }` or a string saying what is missing. */
function form(box, html, build, label) {
  box.innerHTML = html + '<div id="plSay"></div><button type="button" class="cta" id="plGo">' + esc(label) + '</button>';
  const say = box.querySelector('#plSay'), go = box.querySelector('#plGo');
  let armed = null;
  const refresh = () => { armed = null; go.textContent = label; const b = build(); say.innerHTML = typeof b === 'string' ? (b ? '<div class="note">' + esc(b) + '</div>' : '') : '<div class="note">' + b.line + '</div>'; };
  box.querySelectorAll('input').forEach((i) => i.addEventListener('input', refresh));
  go.addEventListener('click', async () => {
    const b = build();
    if (typeof b === 'string') { said(say, 'warn', esc(b || 'Enter an amount.')); return; }
    if (!armed) { armed = b; go.textContent = 'Confirm: ' + b.confirm; return; } // the cost in dollars, then one more tap
    go.disabled = true;
    said(say, '', 'Your wallet is proving the order. This takes a few seconds; nothing has been sent yet.');
    try {
      const r = await b.go();
      // a removal over several share notes can be accepted in part (the wallet says which part, in its own words)
      if (r && r.complete === false && r.detail) said(say, 'warn', esc(r.detail));
      else said(say, 'ok', esc(ACCEPTED));
    } catch (e) { said(say, 'bad', esc(dex.errText(e))); }
    go.disabled = false; armed = null; go.textContent = label;
  });
  refresh();
  return refresh;
}

// HOW FAR THE PRICE MAY MOVE. A buy, a sale and a swap each state a floor: the least the person accepts. Every order
// of a pool that lands in one block gets one price, and other people's orders in that block move it; below the floor
// the chain hands the whole order back. The floor is the estimate less this setting. One setting for the page, 1 %
// unless the person picks another; the three buttons only change this page's arithmetic (nothing is sent).
let slipBps = 100n;
const SLIPS = [[50n, '0.5 %'], [100n, '1 %'], [300n, '3 %']];
const slipHtml = () => '<div class="stack" style="gap:6px"><span class="muted" id="plSlipLabel">If the price moves before your order is paid, accept at most this much less</span>' +
  '<div class="seg" role="group" aria-labelledby="plSlipLabel">' + SLIPS.map(([b, w]) => '<button type="button" data-slip="' + b + '" aria-pressed="' + (b === slipBps) + '" class="' + (b === slipBps ? 'on' : '') + '">' + w + '</button>').join('') + '</div></div>';
function wireSlip(box, refresh) {
  box.querySelectorAll('[data-slip]').forEach((b) => b.addEventListener('click', () => {
    slipBps = BigInt(b.dataset.slip);
    box.querySelectorAll('[data-slip]').forEach((x) => { x.classList.toggle('on', x === b); x.setAttribute('aria-pressed', String(x === b)); });
    refresh();
  }));
}

function addForm(box, p, mine) {
  const sym = esc(pl.label(p)), haveT = pl.big(mine.token), haveU = pl.big(mine.usdm);
  if (pl.big(p.shares) === 0n) {
    // the first deposit: both amounts, and with them the price
    form(box, '<p class="muted">You are the first: the two amounts you bring set the pool\'s price.</p>' +
      '<div class="leg"><label>' + sym + ' you add (you hold ' + esc(units(haveT)) + ')</label><input id="plT" inputmode="decimal" placeholder="0"></div>' +
      '<div class="leg"><label>USDm you add (you hold ' + esc(money(haveU)) + ')</label><input id="plU" inputmode="decimal" placeholder="0.00"></div>', () => {
      const t = pl.atomic(box.querySelector('#plT').value), u = pl.atomic(box.querySelector('#plU').value);
      if (t == null || u == null || t <= 0n || u <= 0n) return 'Enter both amounts.';
      if (t > haveT) return 'Your wallet holds ' + units(haveT) + ' ' + pl.label(p) + '.';
      if (u > haveU) return 'Your wallet holds ' + money(haveU) + '.';
      if (t > largestNote(mine).t) return splitNote(units(largestNote(mine).t) + ' ' + pl.label(p));
      if (!usdmFits(mine, u)) return usdmWhy(mine, u);
      const each = Number(u) / Number(t);
      return {
        line: 'This opens the pool at ' + esc(dex.price(each)) + ' for one ' + sym + '. You hold all of it but ' + pl.LOCKED_SHARES + ' share units, a dust amount the pool keeps for good so that no later deposit can be rounded away. <b>You can remove your liquidity whenever you want.</b> While it is in, its mix of ' + sym + ' and USDm follows the price: if the price moves, you get back more of one and less of the other.',
        confirm: 'add ' + units(t) + ' ' + pl.label(p) + ' and ' + money(u),
        go: () => pl.add(p.token, t, u),
      };
    }, 'Open the pool');
    return;
  }
  form(box, '<div class="leg"><label>USDm you add (you hold ' + esc(money(haveU)) + ')</label><input id="plU" inputmode="decimal" placeholder="0.00"></div>' +
    '<p class="muted">The matching ' + sym + ' is added with it, at the pool\'s own price (you hold ' + esc(units(haveT)) + ').</p>', () => {
    const u = pl.atomic(box.querySelector('#plU').value);
    if (u == null || u <= 0n) return '';
    const t = pl.matchingTokens(p, u);
    if (u > haveU) return 'Your wallet holds ' + money(haveU) + '.';
    if (t > haveT) return 'This needs ' + units(t) + ' ' + pl.label(p) + ' beside it, and your wallet holds ' + units(haveT) + '.';
    if (!usdmFits(mine, u)) return usdmWhy(mine, u);
    if (t > largestNote(mine).t) return 'This needs ' + units(t) + ' ' + pl.label(p) + ' beside it. ' + splitNote(units(largestNote(mine).t) + ' ' + pl.label(p));
    const s = pl.sharesFor(p, u);
    return {
      line: 'You add ' + esc(money(u)) + ' and about ' + esc(units(t)) + ' ' + sym + '. You will hold about ' + s.part.toFixed(s.part < 1 ? 4 : 2) + ' % of this pool and earn that part of every fee its orders leave. <b>You can remove it whenever you want.</b> While it is in, its mix of ' + sym + ' and USDm follows the price: if the price moves, you get back more of one and less of the other. What does not fit the pool\'s ratio comes straight back to you.',
      confirm: 'add ' + money(u) + ' and ' + units(t) + ' ' + pl.label(p),
      go: () => pl.add(p.token, t, u),
    };
  }, 'Add liquidity');
}

/** The creator's card: what the pool holds for the token's creator, and the button that collects it (shown to the
 *  creator's own wallet only; the wallet decides that from its key, not from this page). */
function creatorCard(box, p) {
  const owedT = pl.big(p.creator_owed_token_atomic), owedU = pl.big(p.creator_owed_usdm_atomic);
  if (owedT <= 0n && owedU <= 0n) { box.innerHTML = '<div class="note">You created ' + esc(pl.label(p)) + '. Your part of every trade\'s fee collects here; there is nothing to collect yet.</div>'; return; }
  const what = esc(units(owedT)) + ' ' + esc(pl.label(p)) + ' and ' + esc(money(owedU));
  box.innerHTML = '<div class="row"><h2>Your creator fees</h2><span class="chip done">yours</span></div>' +
    '<p class="muted">You created ' + esc(pl.label(p)) + ', so part of every trade\'s fee is yours. Waiting in the pool: <b>' + what + '</b>.</p>' +
    '<div id="plCSay"></div><button type="button" class="cta" id="plCGo">Collect fees</button>';
  const say = box.querySelector('#plCSay'), go = box.querySelector('#plCGo');
  let armed = false;
  go.addEventListener('click', async () => {
    if (!armed) { armed = true; go.textContent = 'Confirm: collect ' + units(owedT) + ' ' + pl.label(p) + ' and ' + money(owedU); return; }
    go.disabled = true;
    said(say, '', 'Your wallet is proving the claim. This takes a few seconds; nothing has been sent yet.');
    try { await pl.claim(p.token); said(say, 'ok', esc(ACCEPTED)); } catch (e) { said(say, 'bad', esc(dex.errText(e))); }
    go.disabled = false; armed = false; go.textContent = 'Collect fees';
  });
}

/** Put a token on a launch curve (only where nothing has ever entered the token's pool). */
function launchForm(box, p, mine) {
  const sym = esc(pl.label(p)), haveT = pl.big(mine.token);
  form(box, '<p class="muted">A launch curve sells a supply of ' + sym + ' along one line: the price starts low and rises with every buy. Nobody adds liquidity to a curve; when ' + esc(money(pl.GRADUATION_USDM)) + ' has been bought it becomes a pool at the price it reached.</p>' +
    '<div class="leg"><label>' + sym + ' you put on the curve (you hold ' + esc(units(haveT)) + ')</label><input id="plL" inputmode="decimal" placeholder="0"></div>', () => {
    const t = pl.atomic(box.querySelector('#plL').value);
    if (t == null || t <= 0n) return '';
    if (t > haveT) return 'Your wallet holds ' + units(haveT) + ' ' + pl.label(p) + '.';
    if (t > largestNote(mine).t) return splitNote(units(largestNote(mine).t) + ' ' + pl.label(p));
    if (pl.big(mine.usdm) < pl.FEE_USDM_NEEDED) return pl.needsFeeText;
    const first = Number(pl.LAUNCH_BASE_USDM) / Number(t); // USDm for one whole token at the start of the line
    return {
      line: 'The first ' + sym + ' sells at about ' + esc(dex.price(first)) + '. <b>The ' + esc(units(t)) + ' ' + sym + ' you put on the curve do not come back to you</b>: buyers buy them, and what buyers pay stays in the curve and becomes the pool\'s permanent liquidity. Nobody, you included, can ever take that liquidity out. As the token\'s creator you earn ' + (pl.feeOf(null, 'curve') && pl.feeOf(null, 'pool') ? pl.pctOf(pl.feeOf(null, 'curve').creator) + ' % of every trade on the curve and ' + pl.pctOf(pl.feeOf(null, 'pool').creator) + ' % of every trade in the pool after it' : 'a part of every trade on the curve and in the pool after it (your wallet has not read the chain\'s fee yet)') + '. Keep back any ' + sym + ' you want to hold yourself.',
      confirm: 'put ' + units(t) + ' ' + pl.label(p) + ' on a launch curve for good',
      go: () => pl.launch(p.token, t),
    };
  }, 'Launch on a curve');
}

function removeForm(box, p, mine) {
  const sym = esc(pl.label(p)), have = pl.big(mine.shares);
  const locked = Array.isArray(mine.locked) ? mine.locked.filter((l) => pl.big(l.shares) > 0n) : [];
  if (have <= 0n && !locked.length) { box.innerHTML = '<div class="note">You hold no part of this pool. What you add is yours to remove here, at any time, unless you choose to lock it.</div>'; return; }
  box.innerHTML = '<div id="plRemPlain" class="stack"></div><div id="plRemLocked" class="stack"></div>';
  const plain = box.querySelector('#plRemPlain');
  if (have > 0n) {
    form(plain, '<div class="leg"><label>How much of your part to take out: <b id="plPct">100</b> %</label><input id="plR" type="range" min="1" max="100" value="100" style="font-size:inherit"></div>', () => {
      const pct = BigInt(plain.querySelector('#plR').value || '100');
      plain.querySelector('#plPct').textContent = String(pct);
      const shares = pct === 100n ? have : (have * pct) / 100n;
      if (shares <= 0n) return 'That is less than one share unit.';
      if (pl.big(mine.usdm) < pl.FEE_USDM_NEEDED) return pl.needsFeeText;
      const out = pl.removeEstimate(p, shares);
      return {
        line: 'You get back about ' + esc(units(out.token)) + ' ' + sym + ' and ' + esc(money(out.usdm)) + ', straight to your wallet. Nobody is asked and nobody can refuse it; the figure is the pool\'s as it stands when the block that carries your order is paid.',
        confirm: 'take out ' + units(out.token) + ' ' + pl.label(p) + ' and ' + money(out.usdm),
        go: () => pl.remove(p.token, shares),
      };
    }, 'Remove liquidity');
  }
  // YOUR LOCKED LIQUIDITY, one card a date: before the date it says so and offers nothing (the chain would hand it back);
  // from the date on, take it out, or unlock it and stay in the pool
  const now = pl.lockState(p).nowWeek;
  const lbox = box.querySelector('#plRemLocked');
  lbox.innerHTML = locked.map((l, i) => {
    const s = pl.big(l.shares), w = Number(l.week), out = pl.removeEstimate(p, s), open = now != null && now >= w;
    return '<div class="item" style="grid-template-columns:auto 1fr"><span class="lockchip ' + (open ? 'unlocked' : 'locked') + '">' + (open ? 'unlocked' : 'locked') + '</span>' +
      '<div class="t" style="white-space:normal">' + esc(money(pl.positionUsdm(p, s))) + ' of your liquidity, locked until ' + esc(pl.weekDate(w)) + '</div>' +
      '<div class="s">' + (open
        ? 'Its date has come. Take it out (about ' + esc(units(out.token)) + ' ' + sym + ' and ' + esc(money(out.usdm)) + '), or unlock it and keep it in the pool.' +
          '<div class="row" style="gap:8px;margin-top:8px"><button type="button" class="ghost" data-rl="' + i + '">Take it out</button><button type="button" class="ghost" data-ul="' + i + '">Unlock, stay in</button></div><div data-say="' + i + '"></div>'
        : 'Nobody, you included, can take it out before that day; it earns its part of every fee until then. You can make the lock longer on the Lock tab, never shorter.') + '</div></div>';
  }).join('');
  const act = (btn, label, run) => {
    let armed = false;
    btn.addEventListener('click', async () => {
      const say = lbox.querySelector('[data-say="' + (btn.dataset.rl ?? btn.dataset.ul) + '"]');
      if (pl.big(mine.usdm) < pl.FEE_USDM_NEEDED) { if (say) said(say, 'warn', esc(pl.needsFeeText)); return; }
      if (!armed) { armed = true; btn.textContent = 'Confirm: ' + label; return; }
      btn.disabled = true;
      if (say) said(say, '', 'Your wallet is proving the order. This takes a few seconds; nothing has been sent yet.');
      try { const r = await run(); if (say) said(say, r && r.complete === false && r.detail ? 'warn' : 'ok', esc(r && r.complete === false && r.detail ? r.detail : ACCEPTED)); } catch (e) { if (say) said(say, 'bad', esc(dex.errText(e))); }
      btn.disabled = false; armed = false; btn.textContent = btn.dataset.rl != null ? 'Take it out' : 'Unlock, stay in';
    });
  };
  lbox.querySelectorAll('[data-rl]').forEach((b) => { const l = locked[Number(b.dataset.rl)]; act(b, 'take it out', () => pl.removeLocked(p.token, pl.big(l.shares), Number(l.week))); });
  lbox.querySelectorAll('[data-ul]').forEach((b) => { const l = locked[Number(b.dataset.ul)]; act(b, 'unlock', () => pl.unlock(p.token, pl.big(l.shares), Number(l.week))); });
}

// ⭐ LOCK LIQUIDITY (spec §14; user 2026-11-12: "the optional ability to lock their liquidity on ionswap with the ability
// to select the amount of time/unlock date"). The person picks which of their shares (their unlocked ones, or a lock to
// make longer), how much, and when it unlocks: a length, or any date in a calendar. The chain's unlock dates are Mondays
// 00:00 UTC, so a date is moved to the Monday on or after it, and the page says that Monday before anything is sent.
const LENGTHS = [['1 month', 1], ['3 months', 3], ['6 months', 6], ['1 year', 12], ['2 years', 24], ['4 years', 48]];
function lockForm(box, p, mine) {
  const sym = esc(pl.label(p)), st = pl.lockState(p), now = st.nowWeek;
  const plainHave = pl.big(mine.shares);
  const locked = (Array.isArray(mine.locked) ? mine.locked : []).filter((l) => pl.big(l.shares) > 0n);
  const sources = (plainHave > 0n ? [{ week: 0, shares: plainHave, label: 'Your unlocked shares (' + money(pl.positionUsdm(p, plainHave)) + ')' }] : [])
    .concat(locked.map((l) => ({ week: Number(l.week), shares: pl.big(l.shares), label: (Number(l.week) > now ? 'your shares locked until ' : 'your shares whose lock ended ') + pl.weekDate(Number(l.week)) + ' (' + money(pl.positionUsdm(p, pl.big(l.shares))) + ')' })));
  if (now == null) { box.innerHTML = '<div class="note warn">Your node did not say the chain\'s date yet. Ask again in a moment.</div>'; return; }
  if (!sources.length) { box.innerHTML = '<div class="note">You hold no part of this pool to lock. Add liquidity first; locking it is your choice, never required.</div>'; return; }
  const st2 = { src: 0, months: 6, date: '' };
  const max = now + pl.LOCK_WEEKS_MAX;
  const minDate = new Date(pl.weekStartMs(now + 1)).toISOString().slice(0, 10), maxDate = new Date(pl.weekStartMs(max)).toISOString().slice(0, 10);
  const html = '<p class="muted">Locking shows anyone looking at this pool that this much of its liquidity cannot leave before a date: the pool shows a green lock while more than half of it is locked. Your shares stay in your wallet and keep earning their part of every fee. It is your choice and never required.</p>' +
    (sources.length > 1 ? '<div class="seg" role="group" aria-label="Which shares to lock">' + sources.map((x, i) => '<button type="button" data-src="' + i + '" class="' + (i === 0 ? 'on' : '') + '">' + esc(!x.week ? 'Unlocked shares' : x.week > now ? 'Extend ' + pl.weekDate(x.week) : 'Lock again (was ' + pl.weekDate(x.week) + ')') + '</button>').join('') + '</div>' : '') +
    '<div class="leg"><label>How much: <b id="plLkPct">100</b> % of <span id="plLkSrc"></span></label><input id="plLk" type="range" min="1" max="100" value="100" style="font-size:inherit"></div>' +
    '<div class="stack" style="gap:6px"><span class="muted" id="plLkLenLabel">Lock it for</span><div class="seg" role="group" aria-labelledby="plLkLenLabel">' + LENGTHS.map(([w, m]) => '<button type="button" data-months="' + m + '" class="' + (m === 6 ? 'on' : '') + '">' + esc(w) + '</button>').join('') + '</div></div>' +
    '<div class="leg"><label>or pick the unlock date</label><input id="plLkDate" type="date" min="' + minDate + '" max="' + maxDate + '" style="font-size:inherit"></div>';
  const untilWeek = () => {
    const src = sources[st2.src];
    let w;
    if (st2.date) w = pl.weekOnOrAfter(Date.parse(st2.date + 'T00:00:00Z'));
    else { const d = new Date(); d.setUTCMonth(d.getUTCMonth() + st2.months); w = pl.weekOnOrAfter(d.getTime()); }
    return Math.min(max, Math.max(now + 1, src.week + 1, w));
  };
  const refresh = form(box, html, () => {
    const src = sources[st2.src];
    box.querySelector('#plLkSrc').textContent = src.label;
    const pct = BigInt(box.querySelector('#plLk').value || '100');
    box.querySelector('#plLkPct').textContent = String(pct);
    const shares = pct === 100n ? src.shares : (src.shares * pct) / 100n;
    if (shares <= 0n) return 'That is less than one share unit.';
    if (pl.big(mine.usdm) < pl.FEE_USDM_NEEDED) return pl.needsFeeText;
    const w = untilWeek();
    if (src.week && w <= src.week) return 'A lock can only be made longer than ' + pl.weekDate(src.week) + '.';
    const moved = st2.date && pl.weekStartMs(w) !== Date.parse(st2.date + 'T00:00:00Z');
    return {
      line: 'About ' + esc(money(pl.positionUsdm(p, shares))) + ' of your liquidity (' + esc(units(pl.removeEstimate(p, shares).token)) + ' ' + sym + ' and ' + esc(money(pl.removeEstimate(p, shares).usdm)) + ' today) is locked until <b>' + esc(pl.weekDate(w)) + ', 00:00 UTC</b>' + (moved ? ' (the chain\'s unlock dates are Mondays, so the Monday after the date you picked)' : '') +
        '. <b>Nobody, you included, can take it out before that day</b>, and a lock cannot be undone or shortened; it can be made longer. It keeps earning fees and stays in your wallet as locked shares. Anyone can see that this many shares of the pool are locked until that day; nobody can see that they are yours.',
      confirm: 'lock until ' + pl.weekDate(w),
      go: () => pl.lock(p.token, shares, src.week, w),
    };
  }, 'Lock liquidity');
  box.querySelectorAll('[data-src]').forEach((b) => b.addEventListener('click', () => { st2.src = Number(b.dataset.src); box.querySelectorAll('[data-src]').forEach((x) => x.classList.toggle('on', x === b)); refresh(); }));
  box.querySelectorAll('[data-months]').forEach((b) => b.addEventListener('click', () => { st2.months = Number(b.dataset.months); st2.date = ''; box.querySelector('#plLkDate').value = ''; box.querySelectorAll('[data-months]').forEach((x) => x.classList.toggle('on', x === b)); refresh(); }));
  box.querySelector('#plLkDate').addEventListener('change', (e) => { st2.date = e.target.value || ''; box.querySelectorAll('[data-months]').forEach((x) => x.classList.toggle('on', !st2.date && Number(x.dataset.months) === st2.months)); refresh(); });
}

// ⭐ TOKENOMICS (spec §14.3; user 2026-11-12: "showing total supply, allocations, and other info that helps investors know
// whether or not to invest while preserving privacy and not telling which holder"). Every figure is the chain's: the
// supply its minting object recorded, the pool's own row, the lock table by date. What is NOT shown is said too: who
// holds the token, how many hold it, the largest holders and who provides liquidity are on no page, because the chain
// never shows them to anyone.
function tokenomicsCard(box, p) {
  const sym = esc(pl.label(p)), curve = p.kind === 'curve';
  const supply = p.supply == null ? null : pl.big(p.supply);
  const inPool = pl.big(p.token_atomic), owed = pl.big(p.creator_owed_token_atomic), burned = pl.big(p.burned_token_atomic);
  const price = pl.price(p);
  const pct = (v) => (supply && supply > 0n ? Number((v * 1000000n) / supply) / 10000 : 0);
  const pctText = (v) => { const x = pct(v); return (x >= 10 ? x.toFixed(1) : x.toFixed(x < 1 ? 3 : 2)) + '\u00a0%'; };
  const kv = (k, v) => '<span>' + k + '</span><b>' + v + '</b>';
  let html = '<div class="row"><h2>Tokenomics</h2><span class="muted">from the chain</span></div><div class="tokenomics">';
  if (supply != null && supply > 0n) {
    const wallets = supply > inPool + owed + burned ? supply - inPool - owed - burned : 0n;
    const seg = (cls, v) => (v > 0n ? '<i class="' + cls + '" style="width:' + pct(v).toFixed(3) + '%"></i>' : '');
    html += kv('Total supply', esc(units(supply, 8)) + ' ' + sym) +
      kv('More can be made', 'never') + '<span class="muted" style="grid-column:1/-1;font-size:12.5px">Its whole supply was made in one act, and the right to make more is gone for good.</span>' +
      '<div class="alloc" aria-hidden="true">' + seg(curve ? 'curve' : 'pool', inPool) + seg('owed', owed) + seg('burned', burned) + seg('wallets', wallets) + '</div>' +
      '<div class="legend"><span><i style="background:var(' + (curve ? '--ion-2' : '--ion') + ')"></i>' + (curve ? 'on its launch curve' : 'in this pool') + '</span><span><i style="background:var(--warn)"></i>held for the creator\'s fees</span>' + (burned > 0n ? '<span><i style="background:var(--ink-2)"></i>burned</span>' : '') + '<span><i style="background:var(--veil)"></i>in private wallets</span></div>' +
      kv(curve ? 'On its launch curve, for sale' : 'In this pool', esc(units(inPool)) + ' ' + sym + ' · ' + pctText(inPool)) +
      kv('Creator\'s uncollected fees', esc(units(owed)) + ' ' + sym + ' · ' + pctText(owed)) +
      (burned > 0n ? kv('Burned (when its curve became a pool)', esc(units(burned)) + ' ' + sym + ' · ' + pctText(burned)) : '') +
      kv('In private wallets', esc(units(wallets)) + ' ' + sym + ' · ' + pctText(wallets)) + '<span class="muted" style="grid-column:1/-1;font-size:12.5px">Whose wallets, and how many: never shown, to anyone.</span>';
    if (price != null) {
      const fdv = (Number(supply) / 1e8) * price, liq = pl.whole(p.liquidity_usdm_atomic);
      html += kv('Whole supply at this price', esc(usd(fdv))) + kv('Pool liquidity vs. that', esc(money(p.liquidity_usdm_atomic)) + ' · ' + (fdv > 0 ? ((liq / fdv) * 100).toFixed(liq / fdv < 0.01 ? 3 : 1) : '0') + ' %');
    }
  } else {
    html += kv('Total supply', 'not recorded on your node yet') + '<span class="muted" style="grid-column:1/-1">The chain records a token\'s supply when the object that made it folds; a token made before supply records began has none here.</span>' +
      kv(curve ? 'On its launch curve' : 'In this pool', esc(units(inPool)) + ' ' + sym);
  }
  // the lock schedule: each future unlock date and its part of the pool, and the part no provider can ever take out
  const total = pl.big(p.shares), st = pl.lockState(p);
  if (curve) html += kv('Liquidity lock', pl.lockBadge(p)) + '<span class="muted" style="grid-column:1/-1;font-size:12.5px">A launch curve\'s liquidity can never be taken out, and it stays when the curve becomes a pool.</span>';
  else if (total > 0n) {
    const future = (Array.isArray(p.locks) ? p.locks : []).filter((l) => !l.passed);
    const share = (v) => { const x = Number((pl.big(v) * 1000000n) / total) / 10000; return (x >= 10 ? x.toFixed(1) : x.toFixed(x < 1 ? 3 : 2)) + '\u00a0%'; };
    html += kv('Liquidity lock', pl.lockBadge(p, true)) +
      future.map((l) => kv('Unlocks ' + esc(pl.weekDate(Number(l.week))), share(l.shares) + ' of the pool')).join('') +
      kv('Never removable', share(p.locked_shares) + ' of the pool' + (pl.big(p.locked_shares) * 2n > total ? ' (it came from a launch curve)' : ' (the first deposit\'s dust)')) +
      (future.length ? '' : '<span class="muted" style="grid-column:1/-1">No liquidity of this pool is locked: its providers can take theirs out at any time.</span>');
  }
  const fs = pl.feeOf(p);
  html += kv('Fee on a trade', fs ? pl.pctOf(fs.total) + ' %' : '—') + '<span class="muted" style="grid-column:1/-1;font-size:12.5px">' + (fs ? pl.pctOf(fs.pool) + (curve ? ' % stays in the curve, ' : ' % to the providers, ') + pl.pctOf(fs.creator) + ' % to the creator, ' + pl.pctOf(fs.protocol) + ' % to the network, ' + pl.pctOf(fs.publisher) + ' % to the pool program, as the chain charges it.' : 'The chain reports this pool\'s fee with its pool; your wallet has not read it yet.') + '</span>' +
    kv('Batches settled', String(Number(p.batch || 0))) +
    '</div><div class="note">What no page shows, because the chain never shows it to anyone: who holds ' + sym + ', how many wallets hold it, the largest holders, and who provides liquidity. Inputs and payouts are private notes; only the pool\'s own totals are public.</div>';
  box.innerHTML = html;
}

function orderForm(box, p, mine, selling) {
  const sym = esc(pl.label(p)), haveT = pl.big(mine.token), haveU = pl.big(mine.usdm);
  const refresh = form(box, '<div class="leg"><label>' + (selling ? sym + ' you sell (you hold ' + esc(units(haveT)) + ')' : 'USDm you pay (you hold ' + esc(money(haveU)) + ')') + '</label><input id="plA" inputmode="decimal" placeholder="0"></div>' + slipHtml(), () => {
    const a = pl.atomic(box.querySelector('#plA').value);
    if (a == null || a <= 0n) return '';
    if (selling ? a > haveT : a > haveU) return 'Your wallet holds ' + (selling ? units(haveT) + ' ' + pl.label(p) : money(haveU)) + '.';
    if (selling && a > largestNote(mine).t) return splitNote(units(largestNote(mine).t) + ' ' + pl.label(p));
    if (!selling && !usdmFits(mine, a)) return usdmWhy(mine, a);
    if (selling && haveU < pl.FEE_USDM_NEEDED) return pl.needsFeeText;
    const est = selling ? pl.sellEstimate(p, a) : pl.buyEstimate(p, a);
    if (est == null) return 'Your wallet has not read this pool\'s fee from the chain yet, so there is no estimate to show.';
    const least = pl.floorOf(est, slipBps);
    if (est <= 0n) return 'This pool cannot fill that yet.';
    const fs = pl.feeOf(p);
    const fee = selling || !fs ? null : (a * fs.total) / 10000n;
    return {
      line: 'You get about ' + (selling ? esc(money(est)) : esc(units(est)) + ' ' + sym) + (fee != null ? ' (the pool\'s fee is ' + esc(money(fee)) + ' of what you pay)' : '') + '. Every order for this pool in the same block gets one price, so nobody can step in front of yours. If the block\'s price would give you less than ' + (selling ? esc(money(least)) : esc(units(least)) + ' ' + sym) + ', your whole order comes back to you instead.',
      confirm: (selling ? 'sell ' + units(a) + ' ' + pl.label(p) : 'pay ' + money(a)),
      go: () => (selling ? pl.sell(p.token, a, least) : pl.buy(p.token, a, least)),
    };
  }, selling ? 'Sell ' + pl.label(p) : 'Buy ' + pl.label(p));
  wireSlip(box, refresh);
}

/** THE SWAP TAB: ONE TOKEN FOR ANOTHER, in one order through the two pools. The pool's token is sold here and the chain
 *  itself spends that USDm in the other token's pool, a block later. `st` outlives a redraw of the view: it keeps the
 *  token the person chose while a background read repaints the pool. What each control does: the search lists other
 *  pools (read from the wallet's node); choosing one only fills this form; the button sends ONE order, after the
 *  wallet's own sheet has shown both floors in dollars. */
function swapForm(box, p, mine, st) {
  const sym = esc(pl.label(p)), haveT = pl.big(mine.token), haveU = pl.big(mine.usdm);
  box.innerHTML = '<div id="plSwPick" class="stack"></div><div id="plSwForm" class="stack"></div>';
  const pickBox = box.querySelector('#plSwPick'), formBox = box.querySelector('#plSwForm');
  let turn = 0, typing = 0;
  const chosen = () => {
    const o = st.to, osym = esc(pl.label(o));
    pickBox.innerHTML = '<div class="row"><span class="muted">You receive</span><b>' + osym + '</b><button type="button" class="ghost" id="plSwChange">Change</button></div>';
    pickBox.querySelector('#plSwChange').addEventListener('click', () => { st.to = null; formBox.innerHTML = ''; search(); });
    const refresh = form(formBox, '<div class="leg"><label>' + sym + ' you swap (you hold ' + esc(units(haveT)) + ')</label><input id="plSwA" inputmode="decimal" placeholder="0"></div>' + slipHtml(), () => {
      const a = pl.atomic(formBox.querySelector('#plSwA').value);
      if (a == null || a <= 0n) return '';
      if (a > haveT) return 'Your wallet holds ' + units(haveT) + ' ' + pl.label(p) + '.';
      if (a > largestNote(mine).t) return splitNote(units(largestNote(mine).t) + ' ' + pl.label(p));
      if (haveU < pl.FEE_USDM_NEEDED) return pl.needsFeeText;
      const mid = pl.sellEstimate(p, a), out = mid == null ? null : pl.buyEstimate(o, mid);
      if (mid == null || out == null) return 'Your wallet has not read these pools\' fees from the chain yet, so there is no estimate to show.';
      // the floors: the page's setting under the estimate on the first leg, twice it on the second (which carries
      // the first leg's movement too)
      const leastMid = pl.floorOf(mid, slipBps), least = pl.floorOf(out, slipBps * 2n);
      if (mid <= 0n || out <= 0n || leastMid <= 0n || least <= 0n) return 'These two pools cannot fill that yet.';
      return {
        line: 'You get about ' + esc(units(out)) + ' ' + osym + '. The swap runs through two pools, one block after the other: your ' + sym + ' is sold for about ' + esc(money(mid)) + ', and that buys ' + osym + '. Each pool gives every order of a block one price, so nobody can step in front of yours. If the first pool would give less than ' + esc(money(leastMid)) + ', everything you sold comes back. If the second would give less than ' + esc(units(least)) + ' ' + osym + ', you receive the USDm instead.',
        confirm: 'swap ' + units(a) + ' ' + pl.label(p) + ' for at least ' + units(least) + ' ' + pl.label(o),
        go: () => pl.swap(p.token, o.token, a, leastMid, least),
      };
    }, 'Swap ' + pl.label(p) + ' for ' + pl.label(o));
    wireSlip(formBox, refresh);
  };
  const search = () => {
    pickBox.innerHTML = '<input class="field" id="plSwQ" type="search" autocomplete="off" spellcheck="false" placeholder="Token you want: name, symbol or id" aria-label="Search the token you want to receive, by name, symbol or id">' +
      '<div class="list" id="plSwList"><div class="note">Reading your node…</div></div>';
    const q = pickBox.querySelector('#plSwQ'), list = pickBox.querySelector('#plSwList');
    const load = async () => {
      const mineTurn = ++turn;
      try {
        const r = await pl.list(q.value.trim(), 0, 8);
        if (mineTurn !== turn || !list.isConnected) return;
        const rows = (r.pools || []).filter((o) => o.token !== p.token);
        list.innerHTML = rows.map((o) => '<a class="item" role="button" tabindex="0" data-t="' + esc(o.token) + '" style="cursor:pointer">' +
          '<span class="muted num">→</span><span class="t">' + esc(pl.label(o)) + '</span><b class="num">' + esc(money(o.liquidity_usdm_atomic)) + '</b>' +
          '<span class="s">' + kindChip(o) + ' ' + esc(o.name || 'no name on the chain') + ' · one ' + esc(pl.label(o)) + ' is ' + esc(priceText(o)) + '</span></a>').join('') ||
          '<div class="note">' + (q.value.trim() ? 'No other pool matches “' + esc(q.value.trim()) + '”.' : 'No other token has a pool yet.') + '</div>';
        list.querySelectorAll('[data-t]').forEach((b) => {
          const take = () => { st.to = rows.find((o) => o.token === b.dataset.t) || null; if (st.to) chosen(); };
          b.addEventListener('click', take);
          b.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); take(); } });
        });
      } catch (e) {
        if (mineTurn === turn) list.innerHTML = '<div class="note bad">' + esc(dex.errText(e)) + '</div>';
      }
    };
    q.addEventListener('input', () => { clearTimeout(typing); typing = setTimeout(load, 250); });
    load();
  };
  if (st.to) chosen(); else search();
}

async function poolView(root, token) {
  root.innerHTML = '<a class="ghost" href="#/pools" style="justify-self:start;text-decoration:none">← All pools</a><div id="plBody"><div class="note">Reading your node…</div></div>';
  const body = root.querySelector('#plBody');
  let tab = 'add', drawn = '';
  const swapState = { to: null }; // the token a person chose to swap into: kept across the view's background reads
  const draw = (r) => {
    const mine = r.mine || { shares: '0', token: '0', usdm: '0' };
    const seesMine = !!r.mine; // false when the wallet's user has not let this site see balances
    if (!r.ready) { body.innerHTML = '<div class="note warn">Your node is still collecting the pools from the network. This pool appears here on its own.</div>'; return; }
    const p = r.found ? r.pool : { token, symbol: (r.asset && r.asset.symbol) || '', name: (r.asset && r.asset.name) || '', kind: 'pool', token_atomic: '0', usdm_atomic: '0', shares: '0', virtual_usdm_atomic: '0', liquidity_usdm_atomic: '0', price_e12: null, prices: [] };
    const curve = p.kind === 'curve';
    if (curve && (tab === 'add' || tab === 'remove' || tab === 'lock' || tab === 'launch')) tab = 'buy';
    if (!r.found && tab === 'lock') tab = 'add';
    if (!r.found && tab === 'swap') tab = 'add';
    if (r.found && tab === 'launch') tab = 'add';
    const key = JSON.stringify([p, mine, seesMine, r.pending, tab]);
    if (key === drawn) return; // nothing changed: a person's half-typed amount is not wiped by a background read
    drawn = key;
    // (five tabs fit one line on a phone only with one-word labels: a tab's full meaning is its label for a screen
    // reader, its tooltip, and the words of its own form and button)
    const tabs = (curve ? [['buy', 'Buy'], ['sell', 'Sell'], ['swap', 'Swap', 'Swap for another token']] : r.found ? [['add', 'Add', 'Add liquidity'], ['remove', 'Remove', 'Remove liquidity'], ['lock', 'Lock', 'Lock liquidity until a date'], ['buy', 'Buy'], ['sell', 'Sell'], ['swap', 'Swap', 'Swap for another token']] : [['add', 'Open a pool'], ['launch', 'Launch on a curve']]);
    body.innerHTML = '<div class="card stack"><div class="row"><h2>' + esc(pl.label(p)) + ' · USDm</h2><span style="display:inline-flex;gap:6px;flex-wrap:wrap;justify-content:flex-end">' + (r.found ? kindChip(p) + pl.lockBadge(p) : '<span class="chip">not opened yet</span>') + '</span></div>' +
      '<p class="muted">' + esc(p.name || 'no name on the chain') + ' · <span class="mono">' + esc(String(p.token).slice(0, 10)) + '…</span></p>' +
      (r.found ? spark(pl.points(p), 'ionPoolLine') + facts(p, mine) : '<div class="note">Nobody has opened a pool for this token. Open one with a deposit of the token and USDm (yours to take out again at any time), or put a supply of the token on a launch curve (sold along one line; its liquidity is permanent).</div>') +
      (curve ? '<div class="note">This token is still on its launch curve: its whole supply is sold along one line, and nobody adds liquidity to it. When ' + esc(money(pl.GRADUATION_USDM)) + ' has been bought, the curve becomes a pool anyone can add to and remove from.</div>' : '') +
      (r.pending ? '<div class="note">' + r.pending + ' order' + (r.pending === 1 ? '' : 's') + ' for this pool wait' + (r.pending === 1 ? 's' : '') + ' for the next block.</div>' : '') + '</div>' +
      '<div class="card stack"><div class="seg" id="plTabs">' + tabs.map(([k, w, full]) => '<button type="button" data-k="' + k + '" class="' + (k === tab ? 'on' : '') + '"' + (full ? ' aria-label="' + esc(full) + '" title="' + esc(full) + '"' : '') + '>' + esc(w) + '</button>').join('') + '</div><div id="plForm" class="stack"></div></div>' +
      (r.found ? '<div class="card stack" id="plTok"></div>' : '') +
      (r.found && mine.creator ? '<div class="card stack" id="plCreator"></div>' : '');
    body.querySelectorAll('#plTabs button').forEach((b) => b.addEventListener('click', () => { tab = b.dataset.k; drawn = ''; draw(r); }));
    const cc = body.querySelector('#plCreator');
    if (cc) creatorCard(cc, p);
    const tk = body.querySelector('#plTok');
    if (tk) tokenomicsCard(tk, p);
    const f = body.querySelector('#plForm');
    if (!seesMine) f.innerHTML = privateNote(r.mineWhy, 'balances') + '<p class="muted">Adding, removing, buying and selling need to know what your wallet holds. The pool above reads without it.</p>';
    else if (tab === 'add') addForm(f, p, mine);
    else if (tab === 'remove') removeForm(f, p, mine);
    else if (tab === 'lock') lockForm(f, p, mine);
    else if (tab === 'launch') launchForm(f, p, mine);
    else if (tab === 'swap') swapForm(f, p, mine, swapState);
    else orderForm(f, p, mine, tab === 'sell');
  };
  const poll = async () => {
    if (!root.isConnected) return; // the user moved on: the reads stop with the page
    try { draw(await pl.pool(token)); } catch (e) { if (!drawn) body.innerHTML = '<div class="note bad">' + esc(dex.errText(e)) + '</div>'; }
    setTimeout(poll, NEXT_READ_MS);
  };
  poll();
}

export default async function render(view /* , ctx */) {
  const root = document.createElement('section');
  root.className = 'ion page';
  view.appendChild(root);
  if (!S.wallet && !(await learn())) {
    root.innerHTML = '<div><div class="eyebrow">Pools</div><h1>Add liquidity. <em>Take it out whenever you want.</em></h1></div>' + connectNote('to see the pools');
    return;
  }
  const token = (dex.params().get('token') || '').toLowerCase();
  if (pl.isToken(token)) await poolView(root, token);
  else await listView(root);
}
