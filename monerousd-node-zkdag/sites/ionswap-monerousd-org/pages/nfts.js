// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// pages/nfts.js — NFTs (2026-11-10): the ones this wallet holds (put one up for sale, take it back, send it, share
// its card) and the ones it was handed a card for (see whether it is for sale, buy it).
//
// An NFT on MonerousD is an asset whose whole supply is ONE unit, minted once to its creator. Selling it is resting an
// order on the chain's book that offers that one unit for a price; buying it fills that order, and the chain settles
// both sides in one transaction. Nobody watching the chain learns who sold or who bought.
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. Its second party is the wallet that frames it; that crossing is
// exercised with the real wallet and real nodes (scratchpad/net/dex.py), never inside this file.
import { S, learn, esc, usd, connectNote, hiddenNote, isHidden } from '../lib/native.js';
import * as dex from '../lib/dex.js';
import * as store from '../lib/artstore.js';
import * as market from '../lib/market.js';

// An NFT's own picture when this device holds its card (lib/artstore.js: every card there was read by the wallet, which
// refuses a picture that is not the NFT's own); otherwise a pattern drawn from its tag, which claims nothing.
const pictures = new Map(); // tag -> an object URL of its picture
const art = (a) => {
  const url = pictures.get(a.tag);
  if (url) return '<div class="art pic"><img alt="" src="' + url + '" /></div>';
  const h = parseInt(String(a.tag).slice(0, 6), 16) % 360, h2 = parseInt(String(a.tag).slice(6, 12), 16) % 360;
  return '<div class="art" style="background:linear-gradient(135deg, hsl(' + h + ' 85% 55%), hsl(' + h2 + ' 80% 32%))">' + esc(dex.label(a).slice(0, 2).toUpperCase()) + '</div>';
};
// far above any NFT's price: the quote then names the price of the one unit, or says nothing rests
const ANY_PRICE = 1e15;

export default async function render(view /* , ctx */) {
  const root = document.createElement('section');
  root.className = 'ion page';
  root.innerHTML = '<div><div class="eyebrow">NFTs</div><h1>One of a kind, <em>held in private</em></h1>' +
    '<p class="lead">Each NFT is a single unit that only ever exists once. Nobody watching the chain can tell who holds one, who sold it or who bought it.</p></div>' +
    '<div class="two"><div class="stack"><div class="card stack"><div class="row"><h2>Yours</h2><a class="ghost" href="#/studio">Open the studio</a></div><div class="tiles" id="nfMine"><div class="note">Reading your wallet…</div></div></div>' +
    '<div class="card stack"><h2>Find one</h2><p class="muted">Every collection on the chain is in the <a href="#/market">marketplace</a>. Or paste the card an owner or creator shared: your wallet works out the NFT\'s identity from the card itself.</p>' +
    '<textarea class="field" id="nfCard" placeholder="ioncard1…" spellcheck="false" autocapitalize="off" autocomplete="off"></textarea><button class="cta" id="nfAdd" type="button">Look it up</button><div id="nfAddMsg"></div>' +
    '<div class="tiles" id="nfSeen"></div></div></div>' +
    '<div class="card glow stack" id="nfOne"><h2>Pick an NFT</h2><p class="muted">Choose one on the left to sell it, send it, or see whether it is for sale.</p></div></div>';
  view.appendChild(root);
  const $ = (id) => root.querySelector('#' + id);
  const say = (el, kind, text) => { el.innerHTML = text ? '<div class="note ' + kind + '">' + esc(text) + '</div>' : ''; };
  if (!S.wallet && !(await learn())) { $('nfMine').innerHTML = connectNote('to see and trade NFTs'); return; }

  let all = [];
  let open = String(dex.params().get('t') || '').toLowerCase();

  async function one(tag) {
    open = tag;
    const a = dex.find(all, tag);
    const box = $('nfOne');
    root.querySelectorAll('.tile').forEach((t) => t.classList.toggle('on', t.dataset.tag === tag));
    if (!a) { box.innerHTML = '<h2>Pick an NFT</h2><p class="muted">Choose one on the left.</p>'; return; }
    const mine = a.atomic >= 1;
    box.innerHTML = art(a) + '<div><h2>' + esc(a.name || dex.label(a)) + '</h2><div class="muted">' + esc(dex.label(a)) + ' · <span class="mono">' + esc(dex.short(a.tag)) + '</span> · ' + (mine ? 'in your wallet' : 'not yours') + '</div></div>' +
      '<div class="kv" id="nfState"><span>On the book</span><b>Reading…</b></div>' +
      (mine
        ? '<label class="lab">Your price, in dollars<input class="field" id="nfPrice" inputmode="decimal" placeholder="0.00" autocomplete="off" /></label><div class="btns"><button class="cta" id="nfSell" type="button">Put it up for sale</button></div><div class="btns"><button class="ghost" id="nfBack" type="button">Take it off sale</button></div>' +
          '<div class="inline"><input class="field" id="nfTo" placeholder="Send to a MoneroUSD address" spellcheck="false" autocapitalize="off" autocomplete="off" /><button class="ghost" id="nfSend" type="button">Send</button></div>'
        : '<button class="cta" id="nfBuy" type="button" disabled>Reading the book…</button>') +
      '<div id="nfMsg"></div>' + (a.card ? '<div class="cardtext">' + esc(a.card) + '</div><div class="btns" id="nfShare"></div>' : '');
    if (a.card) box.querySelector('#nfShare').appendChild(dex.copyButton(a.card, 'Copy its card'));
    const msg = box.querySelector('#nfMsg');

    let listing = null;
    try {
      const q = await dex.quote(tag, dex.USDM, ANY_PRICE);
      if (open !== tag) return;
      listing = q && q.liquidity && q.total_out >= 1 ? q : null;
      box.querySelector('#nfState').innerHTML = '<span>On the book</span><b>' + (listing ? 'for sale at ' + usd(listing.total_in / dex.UNIT) : 'not for sale') + '</b>';
    } catch (e) { box.querySelector('#nfState').innerHTML = '<span>On the book</span><b>could not be read</b>'; }

    if (!mine) {
      const buy = box.querySelector('#nfBuy');
      buy.disabled = !listing;
      buy.textContent = listing ? 'Buy for ' + usd(listing.total_in / dex.UNIT) : 'Not for sale right now';
      buy.addEventListener('click', async () => {
        if (!listing) return;
        buy.disabled = true; buy.textContent = 'Confirm in your wallet…';
        try {
          const r = await dex.fill(tag, dex.USDM, listing.total_in, 1);
          say(msg, r && r.complete ? 'ok' : 'warn', r && r.complete ? 'Order accepted. It is yours once the next blocks carry it. If another buyer\'s order lands first, your money returns to your wallet.' :'It was not filled: ' + (((r && r.refused) || [])[0] || 'someone else may have bought it first') + '. Nothing was taken.');
          setTimeout(load, 5000);
        } catch (e) { say(msg, 'bad', dex.errText(e)); buy.disabled = false; buy.textContent = 'Buy for ' + usd(listing.total_in / dex.UNIT); }
      });
      return;
    }
    box.querySelector('#nfSell').addEventListener('click', async () => {
      const pay = dex.onGrid(Number(box.querySelector('#nfPrice').value.replace(',', '.')) * dex.UNIT);
      if (!(pay > 0)) { say(msg, 'bad', 'Enter a price.'); return; }
      try {
        const r = await dex.rest(tag, dex.USDM, 1, pay);
        if (r && r.resting) { say(msg, 'ok', 'It is for sale at ' + usd(pay / dex.UNIT) + '. It stays in your wallet until someone buys it; the dollars arrive when they do.'); one(tag); }
        else say(msg, 'warn', 'The book did not take the order: ' + ((r && r.refused) || 'no reason given') + '. Nothing moved.');
      } catch (e) { say(msg, 'bad', dex.NO_EXACT_NOTE.test(String(e && e.message)) ? 'This NFT is still arriving in your wallet. Try again in a block or two. Nothing moved.' : dex.errText(e)); }
    });
    // taking it off sale is moving it to yourself: the order rested on the old note and can no longer be filled
    box.querySelector('#nfBack').addEventListener('click', async () => {
      try { await dex.setAside(tag, 1); say(msg, 'ok', 'It is off sale. Nobody could have refused or delayed that.'); setTimeout(() => one(tag), 4000); } catch (e) { say(msg, 'bad', dex.errText(e)); }
    });
    box.querySelector('#nfSend').addEventListener('click', async () => {
      const to = box.querySelector('#nfTo').value.trim();
      if (!to) { say(msg, 'bad', 'Enter an address.'); return; }
      try { await dex.send(tag, to, 1); say(msg, 'ok', 'Sent. It cannot be undone.'); setTimeout(load, 5000); } catch (e) { say(msg, 'bad', dex.errText(e)); }
    });
  }

  const tile = (a) => '<button type="button" class="tile" data-tag="' + esc(a.tag) + '">' + art(a) + '<b>' + esc(a.name || dex.label(a)) + '</b><span class="muted">' + esc(dex.label(a)) + '</span></button>';
  async function load() {
    try {
      all = await dex.holdings();
      // the cards this device keeps (made in the studio, or looked up here): name the pieces the wallet holds but
      // cannot name yet, and show each one's own picture
      const kept = await store.all();
      let named = false;
      for (const k of kept) {
        const held = dex.find(all, k.tag);
        if (held && held.kind === 'unknown' && k.card) { try { await dex.addCard(k.card); named = true; } catch (_) { /* a card the wallet refuses names nothing */ } }
        if (k.art_hex && !pictures.has(k.tag)) pictures.set(k.tag, store.pictureUrl(k));
      }
      if (named) all = await dex.holdings();
      for (const a of all) if (!a.card) { const k = kept.find((x) => x.tag === a.tag); if (k) a.card = k.card; }
      const nfts = all.filter((a) => a.kind === 'nft');
      const mine = nfts.filter((a) => a.atomic >= 1), seen = nfts.filter((a) => a.atomic < 1);
      const paintTiles = () => {
        $('nfMine').innerHTML = mine.length ? mine.map(tile).join('') : '<div class="note">None yet. Make a collection in the studio, or buy one in the <a href="#/market">marketplace</a>.</div>';
        $('nfSeen').innerHTML = seen.map(tile).join('');
        root.querySelectorAll('.tile').forEach((t) => t.addEventListener('click', () => one(t.dataset.tag)));
      };
      paintTiles();
      if (open && dex.find(all, open)) one(open);
      // a piece no card on this device pictures: the chain's own picture (the creation wrote it into the chain's
      // record), read through the wallet's node by the piece's id, then the tiles are drawn once more
      const unpictured = nfts.filter((a) => a.id && !pictures.has(a.tag));
      if (unpictured.length) {
        const got = await Promise.all(unpictured.map(async (a) => { const url = await market.picture(a.id); if (url) pictures.set(a.tag, url); return !!url; }));
        if (got.some(Boolean) && root.isConnected) { paintTiles(); if (open && dex.find(all, open)) one(open); }
      }
    } catch (e) { $('nfMine').innerHTML = isHidden(e) ? hiddenNote('NFTs and holdings') : '<div class="note bad">' + esc(dex.errText(e)) + '</div>'; }
  }
  $('nfAdd').addEventListener('click', async () => {
    try {
      const c = await dex.addCard($('nfCard').value);
      if (c.art_hex) await store.keep({ tag: c.tag, card: c.card, symbol: c.symbol, name: c.name, kind: c.kind, art_hex: c.art_hex, art_mime: c.art_mime });
      if (c.kind !== 'nft') { location.hash = '#/token?t=' + c.tag; return; }
      open = c.tag;
      say($('nfAddMsg'), '', '');
      await load();
    } catch (e) { say($('nfAddMsg'), 'bad', dex.errText(e)); }
  });
  load();
}
