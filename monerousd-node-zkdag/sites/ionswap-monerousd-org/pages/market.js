// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// pages/market.js — THE NFT MARKETPLACE (2026-11-11): browse every collection on the chain, find one by its handle or
// a piece by its id, open a collection, see each piece and whether it is for sale, buy it.
//
// Nothing here is a list this app keeps. A collection, its pieces, their names and their pictures are the chain's own
// record, read from one node's own copy (lib/market.js). Whether a piece is for sale, and at what price, is the chain's
// order book, asked through the connected wallet (lib/dex.js). What each control does, end to end:
//   * the search box: a piece's id (64 characters) or tag (48) opens that piece; anything else is read as a
//     collection's handle and opens that collection
//   * a collection tile: opens the collection (its record, its cover and a first page of pieces)
//   * More: asks the node for the next range of the same list
//   * a piece tile: opens the piece (its record and picture, and the book's price for its one unit)
//   * Buy: asks the WALLET to fill the resting order; the wallet shows the cost in dollars in its own sheet and asks
//     before anything moves; the chain settles both sides in one transaction
//   * Connect wallet (shown where a wallet is needed): connects it on this page
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. Its second parties are the wallet that answers it and the node
// behind that wallet; those crossings are exercised with the real wallet and real nodes (scratchpad/net/market.py).
import { S, learn, esc, usd, connectNote } from '../lib/native.js';
import * as dex from '../lib/dex.js';
import * as market from '../lib/market.js';

// far above any NFT's price: the quote then names the price of the one unit, or says nothing rests
const ANY_PRICE = 1e15;
const shortId = (id) => String(id || '').slice(0, 8) + '…' + String(id || '').slice(-4);
const go = (params) => { location.hash = '#/market' + (params ? '?' + params : ''); };

// A tile's picture box: a pattern drawn from the id at once (it claims nothing), replaced by the chain's own picture
// when the node answers with one.
function artBox(seed, letters, big) {
  const s = String(seed || '0').padEnd(12, '0');
  const h = parseInt(s.slice(0, 6), 16) % 360, h2 = parseInt(s.slice(6, 12), 16) % 360;
  const box = document.createElement('div');
  box.className = 'art' + (big ? ' big' : '');
  box.style.background = 'linear-gradient(135deg, hsl(' + (h || 24) + ' 85% 55%), hsl(' + (h2 || 280) + ' 80% 32%))';
  box.textContent = String(letters || '').slice(0, 2).toUpperCase();
  return box;
}
function showPicture(box, url) {
  if (!url) return;
  const img = document.createElement('img');
  img.alt = '';
  img.src = url;
  box.textContent = '';
  box.style.background = '';
  box.classList.add('pic');
  box.appendChild(img);
}
// a hex seed for a collection's pattern, from its handle
const seedOf = (text) => Array.from(String(text)).reduce((n, ch) => (n * 33 + ch.charCodeAt(0)) >>> 0, 5381).toString(16).padStart(12, '0');

export default async function render(view /* , ctx */) {
  const root = document.createElement('section');
  root.className = 'ion page';
  root.innerHTML = '<div><div class="eyebrow">NFT marketplace</div><h1>Every collection, <em>straight from the chain</em></h1>' +
    '<p class="lead">Names and pictures here are what the chain itself recorded when each piece was made. Nobody watching the chain can tell who holds a piece, who sold it or who bought it.</p></div>' +
    '<form class="inline" id="mkFind"><input class="field" id="mkQ" placeholder="A collection\'s handle, or a piece\'s id" spellcheck="false" autocapitalize="off" autocomplete="off" />' +
    '<button class="cta" type="submit">Find</button><a class="ghost" href="#/market">All collections</a><a class="ghost" href="#/nfts">Yours</a><a class="ghost" href="#/studio">Make one</a></form>' +
    '<div id="mkBody"><div class="note">Reading the chain\'s record…</div></div>';
  view.appendChild(root);
  const $ = (id) => root.querySelector('#' + id);
  const body = $('mkBody');
  const fail = (e) => {
    const words = String((e && e.message) || e) === 'NO_NODE' ? '' : dex.errText(e);
    body.innerHTML = words ? '<div class="note bad">' + esc(words) + '</div>' : connectNote('to browse the marketplace through your own node');
  };

  $('mkFind').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const v = $('mkQ').value.trim();
    if (!v) { go(''); return; }
    go(market.isId(v) || market.isTag(v) ? 'a=' + v.toLowerCase() : 'c=' + encodeURIComponent(market.canonHandle(v)));
  });

  if (!S.wallet) await learn(); // a connected wallet is asked first; with none, the node behind the page is
  if (!(await market.reachable())) { body.innerHTML = connectNote('to browse the marketplace through your own node'); return; }

  const p = dex.params();
  const wanted = String(p.get('a') || '').toLowerCase();
  const handle = market.canonHandle(p.get('c') || '');

  // ── one piece ──────────────────────────────────────────────────────────────────────────────────────────────────
  async function piece() {
    let a;
    try { a = await market.asset(wanted); } catch (e) { fail(e); return; }
    if (!a || a.found !== true) {
      body.innerHTML = '<div class="note warn">The chain holds no asset with the id <span class="mono">' + esc(shortId(wanted)) + '</span>. Check the id; a piece made in the last few blocks appears once its block has settled.</div>';
      return;
    }
    const name = a.name || a.symbol || 'Untitled';
    body.innerHTML = '<div class="two"><div class="card stack" id="mkArt"></div>' +
      '<div class="card glow stack"><div><h2>' + esc(name) + '</h2><div class="muted">' + esc(a.symbol || '') + (a.kind === 'nft' ? ' · one of a kind' : ' · token') + '</div></div>' +
      (a.collection ? '<div class="kv"><span>Collection</span><b><a href="#/market?c=' + encodeURIComponent(a.collection) + '">' + esc(a.collection) + '</a></b></div>' : '') +
      '<div class="kv"><span>Its id</span><b class="mono">' + esc(shortId(a.id)) + '</b></div>' +
      '<div class="kv"><span>Made by</span><b class="mono">' + esc(shortId(a.creator)) + '</b></div>' +
      '<div id="mkTrade"></div><div id="mkMsg"></div><div class="btns" id="mkShare"></div></div></div>';
    const box = artBox(a.id, a.symbol || name, true);
    body.querySelector('#mkArt').appendChild(box);
    if (a.has_art) market.picture(a.id).then((url) => showPicture(box, url));
    body.querySelector('#mkShare').appendChild(dex.copyButton(a.id, 'Copy its id'));
    const trade = body.querySelector('#mkTrade'), msg = body.querySelector('#mkMsg');
    if (!S.wallet) { trade.innerHTML = connectNote('to see its price and buy it'); return; }
    trade.innerHTML = '<div class="kv" id="mkState"><span>On the book</span><b>Reading…</b></div><button class="cta" id="mkBuy" type="button" disabled>Reading the book…</button>';
    const buy = trade.querySelector('#mkBuy'), state = trade.querySelector('#mkState');
    const say = (kind, text) => { msg.innerHTML = '<div class="note ' + kind + '">' + esc(text) + '</div>'; };
    let listing = null;
    try {
      const quote = await dex.quote(a.tag, dex.USDM, ANY_PRICE);
      listing = quote && quote.liquidity && quote.total_out >= 1 ? quote : null;
      state.innerHTML = '<span>On the book</span><b>' + (listing ? 'for sale at ' + usd(listing.total_in / dex.UNIT) : 'not for sale') + '</b>';
    } catch (e) { state.innerHTML = '<span>On the book</span><b>could not be read</b>'; say('bad', dex.errText(e)); }
    const label = () => (listing ? 'Buy for ' + usd(listing.total_in / dex.UNIT) : 'Not for sale right now');
    buy.disabled = !listing;
    buy.textContent = label();
    buy.addEventListener('click', async () => {
      if (!listing) return;
      buy.disabled = true; buy.textContent = 'Confirm in your wallet…';
      try {
        const r = await dex.fill(a.tag, dex.USDM, listing.total_in, 1);
        // the node has ACCEPTED the order; the purchase is made when a block carries it. Said as that, never as an arrival.
        if (r && r.complete) { say('ok', 'Order accepted. It is yours once the next blocks carry it, and then shows under Yours. If another buyer\'s order lands first, your money returns to your wallet.'); buy.textContent = 'Order accepted'; }
        else { say('warn', 'It was not filled: ' + (((r && r.refused) || [])[0] || 'someone else may have bought it first') + '. Nothing was taken.'); buy.disabled = false; buy.textContent = label(); }
      } catch (e) { say('bad', dex.errText(e)); buy.disabled = false; buy.textContent = label(); }
    });
  }

  // one piece's tile: its id now, its name and picture as the node answers
  function pieceTile(id) {
    const t = document.createElement('a');
    t.className = 'tile';
    t.href = '#/market?a=' + id;
    const box = artBox(id, '');
    const name = document.createElement('b');
    name.textContent = shortId(id);
    const sub = document.createElement('span');
    sub.className = 'muted';
    t.append(box, name, sub);
    market.asset(id).then((a) => {
      if (!a || a.found !== true) return;
      name.textContent = a.name || a.symbol || 'Untitled';
      sub.textContent = a.symbol || '';
      if (!box.classList.contains('pic')) box.textContent = String(a.symbol || a.name || '').slice(0, 2).toUpperCase();
      if (a.has_art) market.picture(id).then((url) => showPicture(box, url));
    }).catch(() => { /* the tile keeps its id */ });
    return t;
  }
  const moreButton = (words, next) => {
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'ghost'; b.textContent = words;
    b.addEventListener('click', async () => { b.disabled = true; try { await next(); } catch (e) { b.disabled = false; b.textContent = 'Could not read more. Try again'; } });
    return b;
  };

  // ── one collection ─────────────────────────────────────────────────────────────────────────────────────────────
  async function oneCollection() {
    let c;
    try { c = await market.collection(handle, 0, true); } catch (e) { fail(e); return; }
    if (!c || c.found !== true) {
      body.innerHTML = '<div class="note warn">The chain holds no collection called "' + esc(handle) + '". Handles are exact: check the spelling, or browse all collections.</div>';
      return;
    }
    body.innerHTML = '<div class="card stack"><div class="row" id="mkHead"></div>' + (c.text ? '<p>' + esc(c.text) + '</p>' : '') + '</div>' +
      '<div class="tiles" id="mkPieces"></div><div class="btns" id="mkMore"></div>';
    const head = body.querySelector('#mkHead');
    const coverBox = artBox(seedOf(c.handle), c.title || c.handle);
    coverBox.style.width = '84px';
    market.cover(c.handle).then((url) => showPicture(coverBox, url));
    const words = document.createElement('div');
    words.innerHTML = '<h2>' + esc(c.title || c.handle) + '</h2><div class="muted">' + esc(c.handle) + ' · ' + esc(String(c.total || 0)) + ' piece(s) · made by <span class="mono">' + esc(shortId(c.owner)) + '</span></div>';
    head.append(coverBox, words);
    const grid = body.querySelector('#mkPieces'), more = body.querySelector('#mkMore');
    let shown = 0;
    const add = (page) => {
      for (const id of page.pieces || []) { grid.appendChild(pieceTile(id)); shown += 1; }
      more.replaceChildren();
      if (shown < (page.total || 0)) more.appendChild(moreButton('More pieces', async () => add(await market.collection(handle, shown))));
      if (!grid.children.length) grid.innerHTML = '<div class="note">This collection has no pieces yet.</div>';
    };
    add(c);
  }

  // ── every collection, newest first ─────────────────────────────────────────────────────────────────────────────
  async function browse() {
    let first;
    try { first = await market.collections(0); } catch (e) { fail(e); return; }
    body.innerHTML = '<div class="tiles" id="mkCols"></div><div class="btns" id="mkMore"></div>';
    const grid = body.querySelector('#mkCols'), more = body.querySelector('#mkMore');
    let shown = 0;
    const add = (page) => {
      for (const c of page.collections || []) {
        const t = document.createElement('a');
        t.className = 'tile';
        t.href = '#/market?c=' + encodeURIComponent(c.handle);
        const box = artBox(seedOf(c.handle), c.title || c.handle);
        if (c.has_cover) market.cover(c.handle).then((url) => showPicture(box, url));
        const name = document.createElement('b');
        name.textContent = c.title || c.handle;
        const sub = document.createElement('span');
        sub.className = 'muted';
        sub.textContent = String(c.pieces || 0) + ' piece(s)';
        t.append(box, name, sub);
        grid.appendChild(t);
        shown += 1;
      }
      more.replaceChildren();
      if (shown < (page.total || 0)) more.appendChild(moreButton('More collections', async () => add(await market.collections(shown))));
      if (!grid.children.length) grid.innerHTML = '<div class="note">No collection has been made on this chain yet. <a href="#/studio">Make the first one in the studio.</a></div>';
    };
    add(first);
  }

  if (wanted && (market.isId(wanted) || market.isTag(wanted))) { $('mkQ').value = wanted; await piece(); }
  else if (handle) { $('mkQ').value = handle; await oneCollection(); }
  else await browse();
}
