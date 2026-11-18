// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// pages/tokens.js — tokens made on MonerousD (2026-11-10): the ones this wallet holds or was handed a card for, and
// one token's market (buy, sell, rest an order at your own price, send, share its card).
//
// Every action is asked of the wallet that frames this page; the wallet shows the cost in dollars and acts. A price
// here is read from the chain's own order book through the wallet's node: an exact quote, never an estimate.
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. Its second party is the wallet that frames it; that crossing is
// exercised with the real wallet and real nodes (scratchpad/net/dex.py), never inside this file.
import { S, learn, esc, usd, connectNote, hiddenNote, isHidden } from '../lib/native.js';
import * as dex from '../lib/dex.js';
import * as store from '../lib/artstore.js';
import * as chain from '../lib/market.js';
import * as pools from '../lib/pools.js';

const need = connectNote('to see and trade tokens');

// ── the list ────────────────────────────────────────────────────────────────────────────────────────────────
async function list(root) {
  root.innerHTML = '<div><div class="eyebrow">Tokens</div><h1>Trade any <em>token</em></h1>' +
    '<p class="lead">Tokens made on MonerousD trade against MoneroUSD: in their own pools, at one price a block, and on the chain\'s order book at a price of your own. Nobody watching the chain sees who made an order or who took it.</p></div>' +
    // every token that has a pool, the deepest first, with a search over all of them (the wallet's node's own copy of
    // the pools; no server is asked which token a person looks for). A row opens the token's pool: buy, sell, swap.
    '<div class="card stack"><input class="field" id="tkQ" type="search" autocomplete="off" spellcheck="false" placeholder="Search tokens: name, symbol or id" aria-label="Search every token that has a pool, by its name, its symbol or its id">' +
    '<div class="row"><b id="tkHead">Top tokens by liquidity</b><span class="muted" id="tkCount"></span></div>' +
    '<div class="list" id="tkTop"><div class="note">Reading your node…</div></div>' +
    '<button type="button" class="ghost" id="tkMore" hidden>Show more</button></div>' +
    '<div class="two"><div class="card stack"><div class="row"><h2>In your wallet</h2><a class="ghost" href="#/create">Launch a token</a></div><div class="list" id="tkList"><div class="note">Reading your wallet…</div></div></div>' +
    '<div class="card stack"><h2>Find a token</h2><p class="muted">Paste a token\'s id and its name comes from the chain\'s own record, which nobody but its creator could write. Or paste the card its creator shared: your wallet works out the token\'s identity from the card itself.</p>' +
    '<textarea class="field" id="tkCard" placeholder="A token\'s id, or ioncard1…" spellcheck="false" autocapitalize="off" autocomplete="off"></textarea>' +
    '<button class="cta" id="tkAdd" type="button">Find it</button><div id="tkAddMsg"></div></div></div>';
  // ── top tokens and the search: what the control does is read; nothing is sent or spent
  const top = root.querySelector('#tkTop'), more = root.querySelector('#tkMore'), q = root.querySelector('#tkQ');
  const TOP_PAGE = 25;
  let shown = 0, query = '', turn = 0, typing = 0;
  const topRow = (p, rank) => '<a class="item" href="#/pools?token=' + esc(p.token) + '">' +
    '<span class="muted num" style="min-width:2ch;text-align:right">' + rank + '</span>' +
    '<div class="t">' + esc(pools.label(p)) + (p.name && p.name !== p.symbol ? ' <span class="muted">' + esc(p.name) + '</span>' : '') + '</div>' +
    '<span class="amt">' + esc(p.price_e12 == null ? 'no price yet' : dex.price(pools.price(p))) + '</span>' +
    '<div class="s">' + (p.kind === 'curve' ? 'on its launch curve' : 'in its pool') + ' · ' + esc(usd(pools.whole(p.liquidity_usdm_atomic))) + ' of liquidity</div></a>';
  const loadTop = async (reset) => {
    const mine = ++turn;
    if (!S.wallet && !(await learn())) { top.innerHTML = need; more.hidden = true; return; }
    if (reset) { shown = 0; top.innerHTML = '<div class="note">Reading your node…</div>'; }
    try {
      const r = await pools.list(query, shown, TOP_PAGE);
      if (mine !== turn || !root.isConnected) return;
      if (!r.ready) {
        top.innerHTML = '<div class="note warn">Your node is still collecting the pools from the network. The tokens appear here on their own.</div>';
        more.hidden = true;
        return;
      }
      const rows = (r.pools || []).map((p, i) => topRow(p, shown + i + 1)).join('');
      if (reset) top.innerHTML = rows || '<div class="note">' + (query ? 'No token with a pool matches “' + esc(query) + '”. A token with no pool yet is found by its id, below.' : 'No token has a pool yet. Launch one, or open a pool for a token you hold.') + '</div>';
      else top.insertAdjacentHTML('beforeend', rows);
      shown += (r.pools || []).length;
      root.querySelector('#tkHead').textContent = query ? 'Tokens matching “' + query + '”' : 'Top tokens by liquidity';
      root.querySelector('#tkCount').textContent = r.total + (r.total === 1 ? ' token' : ' tokens');
      more.hidden = shown >= r.total;
    } catch (e) {
      if (mine === turn) top.innerHTML = '<div class="note bad">' + esc(dex.errText(e)) + '</div>';
    }
  };
  q.addEventListener('input', () => { clearTimeout(typing); typing = setTimeout(() => { query = q.value.trim(); loadTop(true); }, 250); });
  more.addEventListener('click', () => loadTop(false));
  loadTop(true);

  const box = root.querySelector('#tkList');
  const paint = async () => {
    if (!S.wallet && !(await learn())) { box.innerHTML = need; return; }
    try {
      const all = (await dex.holdings()).filter((a) => a.kind !== 'nft');
      const rank = (a) => (a.symbol === 'USDm' ? 0 : a.symbol === 'SAT' ? 1 : 2);
      all.sort((x, y) => rank(x) - rank(y) || dex.label(x).localeCompare(dex.label(y)));
      box.innerHTML = all.length ? all.map((a) => {
        const inner = dex.dot(a) + '<div class="t">' + esc(dex.label(a)) + (a.name && a.name !== a.symbol ? ' <span class="muted">' + esc(a.name) + '</span>' : '') + '</div>' +
          '<span class="amt">' + esc(dex.amountText(a, a.atomic)) + '</span>' +
          '<div class="s mono">' + (a.kind === 'coin' ? (a.symbol === 'USDm' ? 'what every token here is priced in' : 'traded on the Swap tab') : esc(dex.short(a.tag)) + (a.kind === 'unknown' ? ' · its name appears once the chain\'s record of it has settled' : '')) + '</div>';
        // a pool's share notes open their pool (where they are handed back for both assets), never an order book
        if (a.kind === 'share' && a.pool) return '<a class="item" href="#/pools?token=' + esc(a.pool) + '">' + inner + '</a>';
        return a.kind === 'coin' ? '<div class="item">' + inner + '</div>' : '<a class="item" href="#/token?t=' + esc(a.tag) + '">' + inner + '</a>';
      }).join('') : '<div class="note">No tokens yet. Launch one, or find one by its id.</div>';
    } catch (e) { box.innerHTML = isHidden(e) ? hiddenNote('balances and tokens') : '<div class="note bad">' + esc(dex.errText(e)) + '</div>'; }
  };
  root.querySelector('#tkAdd').addEventListener('click', async () => {
    const msg = root.querySelector('#tkAddMsg');
    const text = root.querySelector('#tkCard').value.trim();
    try {
      // an id (64 characters) or a tag (48): the chain's own record names it, read through the wallet's node
      if (chain.isId(text) || chain.isTag(text)) {
        const a = await chain.asset(text);
        if (!a || a.found !== true) { msg.innerHTML = '<div class="note warn">The chain holds no token with that id. Check it; a token made in the last few blocks appears once its block has settled.</div>'; return; }
        location.hash = a.kind === 'nft' ? '#/market?a=' + a.id : '#/token?t=' + a.tag;
        return;
      }
      const c = await dex.addCard(text);
      location.hash = (c.kind === 'nft' ? '#/nfts?t=' : '#/token?t=') + c.tag;
    } catch (e) { msg.innerHTML = String((e && e.message) || e) === 'NO_NODE' ? need : '<div class="note bad">' + esc(dex.errText(e)) + '</div>'; }
  });
  paint();
}

// ── one token's market ──────────────────────────────────────────────────────────────────────────────────────
async function market(root, tag) {
  root.innerHTML = '<div class="note">Reading your wallet…</div>';
  if (!S.wallet && !(await learn())) { root.innerHTML = need; return; }
  let all = await dex.holdings();
  let tk = dex.find(all, tag) || { tag, atomic: 0, symbol: null, name: null, kind: 'unknown', card: null };
  // this wallet does not hold the token and keeps no card of it: ONE read of its record, by id, names it
  if (tk.kind === 'unknown') {
    try { const a = await chain.asset(tag); if (a && a.found === true) tk = Object.assign({}, tk, { symbol: a.symbol, name: a.name, kind: a.kind, id: a.id }); } catch (_) { /* it stays unnamed */ }
  }
  const sym = () => dex.label(tk);
  const st = { side: 'buy', amount: '', q: null, busy: false };
  // the token's own picture, when this device keeps its card (the wallet refused any picture that is not the token's own)
  const kept = await store.get(tag);
  if (kept && !tk.card) tk.card = kept.card;
  // ...or, with no card here, its picture as nodes keep it: ONE read by the token's id through the wallet's node
  const chainPic = !(kept && kept.art_hex) && tk.id ? await chain.picture(tk.id) : '';
  const face = kept && kept.art_hex ? '<span class="coin pic"><img alt="" src="' + store.pictureUrl(kept) + '" /></span>'
    : chainPic ? '<span class="coin pic"><img alt="" src="' + chainPic + '" /></span>' : dex.dot(tk);

  root.innerHTML = '<div class="head">' + face + '<h1>' + esc(sym()) + '</h1><div class="muted">' + esc(tk.name || 'A token with no card yet') + ' · <span class="mono">' + esc(dex.short(tag)) + '</span> · you hold <b id="mkHeld">' + esc(dex.amountText(tk, tk.atomic)) + '</b></div></div>' +
    '<div class="two"><div class="stack">' +
      '<div class="card stack" id="mkPool" hidden></div>' +
      '<div class="card glow stack"><div class="seg" role="tablist"><button type="button" data-side="buy" class="on">Buy</button><button type="button" data-side="sell">Sell</button></div>' +
        '<div class="leg"><label id="mkLab">You pay</label><input id="mkAmt" inputmode="decimal" placeholder="0" autocomplete="off" /><span class="asset fixed" id="mkUnit">USDm</span><div class="sub" id="mkSub"></div></div>' +
        '<div class="kv" id="mkQuote"></div><button class="cta" id="mkGo" type="button" disabled>Enter an amount</button><div id="mkMsg"></div></div>' +
      '<div class="card stack"><h2>Sell at your own price</h2><p class="muted">Rest an order on the book. It stays in your wallet until someone fills it, and taking it back is one tap.</p>' +
        '<label class="lab">How many ' + esc(sym()) + '<input class="field" id="lsLot" inputmode="decimal" placeholder="0" autocomplete="off" /></label>' +
        '<label class="lab">Price for each, in dollars<input class="field" id="lsPrice" inputmode="decimal" placeholder="0.00" autocomplete="off" /></label>' +
        '<div class="note" id="lsGrid" hidden></div>' +
        '<div class="stepline" id="lsS1"><em>1</em><span>Set the amount aside in your own wallet</span><button class="ghost" id="lsAside" type="button" disabled>Set aside</button></div>' +
        '<div class="stepline" id="lsS2"><em>2</em><span>Rest the order on the book</span><button class="ghost" id="lsRest" type="button" disabled>Rest it</button></div><div id="lsMsg"></div></div>' +
    '</div><div class="stack">' +
      '<div class="card stack"><div class="row"><h2>The book</h2><button class="ghost" id="bkAgain" type="button">Refresh</button></div><p class="muted">Orders resting right now, counted by price band. Every order in a band is one equal lot, so a count shows no one\'s size.</p>' +
        '<div class="muted">Selling ' + esc(sym()) + '</div><div class="levels" id="bkAsks"><div class="muted">Reading…</div></div><div class="muted">Buying ' + esc(sym()) + '</div><div class="levels bids" id="bkBids"></div></div>' +
      '<div class="card stack"><h2>Send</h2><input class="field" id="sdTo" placeholder="A MoneroUSD address" spellcheck="false" autocapitalize="off" autocomplete="off" />' +
        '<div class="inline"><input class="field" id="sdAmt" inputmode="decimal" placeholder="How many ' + esc(sym()) + '" autocomplete="off" /><button class="ghost" id="sdGo" type="button">Send</button></div><div id="sdMsg"></div></div>' +
      '<div class="card stack"><h2>Supply and who holds it</h2><div class="kv"><span>Supply</span><b>fixed for ever</b><span>Who can make more</span><b>nobody</b><span>At launch</span><b>its creator held all of it</b></div>' +
        '<p class="muted">Every token here is minted once, whole, to its creator, and the right to mint is used up in that step. Whatever is for sale came from that one holding.</p></div>' +
      '<div class="card stack"><h2>Share this token</h2>' + (tk.card ? '<p class="muted">Anyone who adds this card sees ' + esc(sym()) + ' by name and can trade it. The card proves its own name; it holds no key.</p><div class="cardtext">' + esc(tk.card) + '</div><div class="btns" id="shBtns"></div>' : '<p class="muted">Your wallet holds this token but not its card, so it has no name here yet. Ask its creator for the card and add it on the Tokens page.</p>') + '</div>' +
    '</div></div>';
  if (tk.card) root.querySelector('#shBtns').appendChild(dex.copyButton(tk.card, 'Copy the card'));
  const $ = (id) => root.querySelector('#' + id);
  // the token's POOL, when the chain names the token (one read through the wallet's node): its price and the way in.
  // The pool is where most trading happens; the book below is for an order at a price of your own.
  if (tk.id && tk.kind !== 'nft') {
    pools.pool(tk.id).then((r) => {
      const box = root.querySelector('#mkPool');
      if (!box || !r || !r.ready) return;
      const p = r.found ? r.pool : null;
      box.hidden = false;
      box.innerHTML = p
        ? '<div class="row"><h2>' + esc(sym()) + ' · USDm ' + (p.kind === 'curve' ? 'launch curve' : 'pool') + '</h2><span class="chip done">one price a block</span></div>' +
          '<div class="kv"><span>One ' + esc(sym()) + '</span><b>' + esc(p.price_e12 == null ? 'no price yet' : dex.price(pools.price(p))) + '</b><span>Liquidity</span><b>' + esc(usd(pools.whole(p.liquidity_usdm_atomic))) + '</b></div>' +
          '<a class="cta" href="#/pools?token=' + esc(tk.id) + '" style="text-align:center;text-decoration:none">Buy or sell through the pool</a>'
        : '<div class="row"><h2>No pool yet</h2></div><p class="muted">Nobody has opened a pool for ' + esc(sym()) + '. Whoever holds some can open one with a deposit, and take that deposit out again at any time.</p>' +
          '<a class="ghost" href="#/pools?token=' + esc(tk.id) + '" style="text-align:center;text-decoration:none">Open its pool</a>';
    }).catch(() => { /* the pool card stays hidden: the book below still works */ });
  }
  const say = (el, kind, text) => { el.innerHTML = text ? '<div class="note ' + kind + '">' + esc(text) + '</div>' : ''; };
  const refreshHeld = async () => {
    try { all = await dex.holdings(); const now = dex.find(all, tag); if (now) { tk = now; $('mkHeld').textContent = dex.amountText(tk, tk.atomic); } } catch (_) { /* shown on the next read */ }
  };

  // buy / sell at the book's price
  let asked = 0;
  const requote = async () => {
    const mine = ++asked;
    const v = Number(st.amount);
    st.q = null;
    $('mkQuote').innerHTML = '';
    $('mkGo').disabled = true;
    if (!(v > 0)) { $('mkGo').textContent = 'Enter an amount'; $('mkSub').textContent = ''; return; }
    $('mkGo').textContent = 'Reading the book…';
    try {
      const buying = st.side === 'buy';
      const q = await (buying ? dex.quote(tag, dex.USDM, v * dex.UNIT) : dex.quote(dex.USDM, tag, v * dex.UNIT));
      if (mine !== asked) return;
      if (!q || !q.liquidity) {
        $('mkGo').textContent = buying ? 'Nobody is selling yet' : 'Nobody is buying yet';
        $('mkQuote').innerHTML = '<span>The book</span><b>' + (buying ? 'no ' + esc(sym()) + ' is offered at this size' : 'no one is bidding at this size') + '</b>';
        $('mkSub').textContent = buying ? '' : 'You can rest your own order below and the first buyer fills it.';
        return;
      }
      st.q = q;
      const paid = q.total_in / dex.UNIT, got = q.total_out / dex.UNIT;
      const each = buying ? paid / got : got / paid;
      $('mkQuote').innerHTML = '<span>You pay</span><b>' + (buying ? usd(paid) : esc(dex.amountText(tk, q.total_in)) + ' ' + esc(sym())) + '</b>' +
        '<span>You receive, exactly</span><b>' + (buying ? esc(dex.amountText(tk, q.total_out)) + ' ' + esc(sym()) : usd(got)) + '</b>' +
        '<span>Price for each ' + esc(sym()) + '</span><b>' + dex.price(each) + '</b>' +
        '<span>Orders filled</span><b>' + esc(q.rungs) + '</b>';
      $('mkSub').textContent = q.shortfall > 0 ? 'The book fills ' + (buying ? usd(paid) : dex.amountText(tk, q.total_in) + ' ' + sym()) + ' of what you entered today; the rest stays with you.' : '';
      $('mkGo').disabled = false;
      $('mkGo').textContent = buying ? 'Buy ' + sym() : 'Sell ' + sym();
    } catch (e) { if (mine === asked) { $('mkGo').textContent = 'Could not read the book'; say($('mkMsg'), 'bad', dex.errText(e)); } }
  };
  let wait = 0;
  $('mkAmt').addEventListener('input', (ev) => { st.amount = ev.target.value.replace(',', '.'); say($('mkMsg'), '', ''); clearTimeout(wait); wait = setTimeout(requote, 350); });
  root.querySelectorAll('[data-side]').forEach((b) => b.addEventListener('click', () => {
    st.side = b.dataset.side;
    root.querySelectorAll('[data-side]').forEach((x) => x.classList.toggle('on', x === b));
    $('mkLab').textContent = st.side === 'buy' ? 'You pay' : 'You sell';
    $('mkUnit').textContent = st.side === 'buy' ? 'USDm' : sym();
    requote();
  }));
  $('mkGo').addEventListener('click', async () => {
    if (!st.q || st.busy) return;
    st.busy = true; $('mkGo').disabled = true; $('mkGo').textContent = 'Confirm in your wallet…';
    try {
      const q = st.q;
      // the floor is the quote itself: the wallet re-reads the book and refuses rather than fill at a worse price
      const r = await (st.side === 'buy' ? dex.fill(tag, dex.USDM, q.total_in, q.total_out) : dex.fill(dex.USDM, tag, q.total_in, q.total_out));
      say($('mkMsg'), r && r.complete ? 'ok' : 'warn', r && r.complete ? r.settled_rungs + ' order(s) accepted. What you bought is yours once the next blocks carry it. If another buyer\'s order lands first, your money returns to your wallet.' : 'Accepted ' + ((r && r.settled_rungs) || 0) + ' of ' + ((r && r.planned_rungs) || 0) + ' order(s). ' + (((r && r.refused) || [])[0] || 'The rest was not filled and nothing was taken for it.'));
      setTimeout(() => { refreshHeld(); book(); }, 4000);
    } catch (e) { say($('mkMsg'), 'bad', dex.errText(e)); }
    st.busy = false; requote();
  });

  // rest an order at your own price: set the exact amount aside, then rest it
  const plan = () => {
    const lot = dex.onGrid(Number($('lsLot').value.replace(',', '.')) * dex.UNIT);
    const price = Number($('lsPrice').value.replace(',', '.'));
    const pay = dex.onGrid((lot / dex.UNIT) * price * dex.UNIT);
    return { lot, pay, ok: lot > 0 && pay > 0 };
  };
  const planned = () => {
    const p = plan();
    $('lsAside').disabled = $('lsRest').disabled = !p.ok;
    $('lsGrid').hidden = !p.ok;
    if (p.ok) $('lsGrid').textContent = 'The order will offer ' + dex.amountText(tk, p.lot) + ' ' + sym() + ' for ' + usd(p.pay / dex.UNIT) + ' in all. Amounts sit on the chain\'s public grid, so every order looks like every other and none can be traced to you.';
  };
  $('lsLot').addEventListener('input', planned);
  $('lsPrice').addEventListener('input', planned);
  $('lsAside').addEventListener('click', async () => {
    const p = plan();
    if (!p.ok) return;
    if (p.lot > tk.atomic) { say($('lsMsg'), 'bad', 'You hold ' + dex.amountText(tk, tk.atomic) + ' ' + sym() + ', less than this order offers.'); return; }
    $('lsAside').disabled = true;
    try {
      await dex.setAside(tag, p.lot);
      $('lsS1').classList.add('done');
      say($('lsMsg'), 'ok', 'Set aside. It is yours the whole time; give it a block or two to arrive, then rest the order.');
    } catch (e) { say($('lsMsg'), 'bad', dex.errText(e)); }
    $('lsAside').disabled = false;
  });
  $('lsRest').addEventListener('click', async () => {
    const p = plan();
    if (!p.ok) return;
    $('lsRest').disabled = true;
    try {
      const r = await dex.rest(tag, dex.USDM, p.lot, p.pay);
      if (r && r.resting) { $('lsS2').classList.add('done'); say($('lsMsg'), 'ok', 'Your order is on the book. The first buyer at this price fills it and the dollars arrive in your wallet. To take it back, set the same amount aside again.'); book(); }
      else say($('lsMsg'), 'warn', 'The book did not take the order: ' + ((r && r.refused) || 'no reason given') + '. Nothing moved.');
    } catch (e) {
      say($('lsMsg'), dex.NO_EXACT_NOTE.test(String(e && e.message)) ? 'warn' : 'bad', dex.NO_EXACT_NOTE.test(String(e && e.message)) ? 'Your wallet has no piece of exactly this amount yet. Do step 1, wait a block or two for it to arrive, then rest the order. Nothing moved.' : dex.errText(e));
    }
    $('lsRest').disabled = false;
  });

  // the book, by price band
  const bars = (d, askSide) => {
    const lv = ((d && d.levels) || []).filter((l) => l.resting > 0);
    if (!lv.length) return '<div class="muted">Nothing resting.</div>';
    const most = Math.max(...lv.map((l) => l.resting));
    return lv.map((l) => {
      // an ask gives the token and is paid dollars; a bid gives dollars and is paid the token
      const each = l.best_cost && l.best_receives ? (askSide ? l.best_cost / l.best_receives : l.best_receives / l.best_cost) : null;
      return '<div class="lv"><span>' + (each == null ? 'band ' + esc(l.level) : 'from ' + dex.price(each)) + '</span><i style="--p:' + Math.round((l.resting / most) * 100) + '%"></i><b>' + esc(l.resting) + '</b></div>';
    }).join('');
  };
  async function book() {
    try {
      const [asks, bids] = await Promise.all([dex.depth(tag, dex.USDM), dex.depth(dex.USDM, tag)]);
      $('bkAsks').innerHTML = bars(asks, true);
      $('bkBids').innerHTML = bars(bids, false);
    } catch (e) { $('bkAsks').innerHTML = '<div class="note bad">' + esc(dex.errText(e)) + '</div>'; }
  }
  $('bkAgain').addEventListener('click', book);

  $('sdGo').addEventListener('click', async () => {
    const amt = Math.floor(Number($('sdAmt').value.replace(',', '.')) * dex.UNIT);
    const to = $('sdTo').value.trim();
    if (!to || !(amt > 0)) { say($('sdMsg'), 'bad', 'Enter an address and an amount.'); return; }
    try { await dex.send(tag, to, amt); say($('sdMsg'), 'ok', 'Sent. It cannot be undone.'); setTimeout(refreshHeld, 4000); } catch (e) { say($('sdMsg'), 'bad', dex.errText(e)); }
  });
  book();
}

export default async function render(view /* , ctx */) {
  const root = document.createElement('section');
  root.className = 'ion page';
  view.appendChild(root);
  const tag = String(dex.params().get('t') || '').toLowerCase();
  try {
    if (/^#\/token(\?|$)/.test(location.hash) && dex.isTag(tag)) await market(root, tag);
    else await list(root);
  } catch (e) { root.innerHTML = isHidden(e) ? hiddenNote('balances and tokens') : '<div class="note bad">' + esc(dex.errText(e)) + '</div>'; }
}
