// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// pages/create.js — launch a token (2026-11-10). NFTs and collections are made in the studio (pages/studio.js).
//
// The chain creates the asset from a Dark Solidity contract its own compiler writes for the kind, symbol and name, and
// mints the whole supply ONCE to the creator: nobody, the creator included, can ever mint more. The creation price is
// the chain's (shorter symbols cost more) and is read from the wallet's own node; the wallet shows it in dollars in its
// own sheet before anything is paid.
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. Its second party is the wallet that frames it; the creation is
// exercised with the real wallet and real nodes (scratchpad/net/dex.py), never inside this file.
import { S, learn, esc, usd, connectNote } from '../lib/native.js';
import * as dex from '../lib/dex.js';
import * as gen from '../lib/artgen.js';
import * as store from '../lib/artstore.js';

export default async function render(view /* , ctx */) {
  const root = document.createElement('section');
  root.className = 'ion page';
  if (dex.params().get('kind') === 'nft') { location.replace('#/studio'); return; }
  const st = { kind: 'token', fee: null, busy: false, art: null };
  root.innerHTML = '<div><div class="eyebrow">Create</div><h1>Launch a <em>token</em></h1>' +
    '<p class="lead">One step. The whole supply arrives in your wallet, fixed for ever, and nobody watching the chain learns who made it.</p></div>' +
    '<div class="two"><div class="card glow stack">' +
      '<label class="drop" id="crDrop"><input type="file" id="crLogo" accept="image/png,image/jpeg,image/webp" hidden /><b id="crDropT">Add its picture (optional)</b><span>kept on the chain with the token, so every wallet and the marketplace show its own picture</span></label>' +
      '<label class="lab">Symbol, letters and digits<input class="field" id="crSym" maxlength="32" placeholder="MOON" autocapitalize="characters" autocomplete="off" spellcheck="false" /></label>' +
      '<label class="lab">Name<input class="field" id="crName" maxlength="128" placeholder="Moon Coin" autocomplete="off" /></label>' +
      '<label class="lab" id="crSupplyLab">How many will ever exist<input class="field" id="crSupply" inputmode="numeric" placeholder="1000000" autocomplete="off" /></label>' +
      '<div class="kv" id="crFacts"></div><button class="cta" id="crGo" type="button" disabled>Enter a symbol and a name</button><div id="crMsg"></div></div>' +
    '<div class="card stack"><h2>What you get</h2><div class="steps">' +
      '<div><div><b>A fixed supply</b><span>Minted once, to you. The right to mint is used up in the same step, so no one can ever make more.</span></div></div>' +
      '<div><div><b>Its name on the chain</b><span>The chain records the name and picture with the token, so every wallet shows them and anyone can find it by its id. Nobody but you could have written them.</span></div></div>' +
      '<div><div><b>A market the moment you want one</b><span>Offer any amount at your own price from the token\'s page; the first buyer fills it.</span></div></div>' +
    '</div><h2>Who holds what, in the open</h2><p class="muted">At launch the creator holds the whole supply: that is how every token here starts, and the token\'s page says so to everyone who opens it. Nobody can ever make more.</p>' +
    '<h2>What a launch costs</h2><div class="kv" id="crTiers"><span>Any symbol, any length</span><b>—</b></div><p class="muted">Set by the chain and read live; it goes to the chain\'s pools, never to this app.</p><div class="steps" hidden>' +
    '</div></div></div><div id="crDone"></div>';
  view.appendChild(root);
  const $ = (id) => root.querySelector('#' + id);
  const sym = () => $('crSym').value.replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 32);
  const supply = () => Math.floor(Number($('crSupply').value.replace(/[,\s]/g, '')));

  // the chain's own launch price, read from the wallet's node (never written into this page)
  const tiers = async () => {
    if (!S.wallet && !(await learn())) return;
    try { const got = await dex.createFee('LAUNCH', 'token'); root.querySelector('#crTiers b').textContent = usd(Number(got && got.fee_atomic) / dex.UNIT); }
    catch (_) { /* the dash stays: a price is never guessed */ }
  };
  let asked = 0;
  const paint = async () => {
    const s = sym(), name = $('crName').value.trim();
    const ready = s && name && (st.kind === 'nft' || supply() >= 1);
    const go = $('crGo');
    go.disabled = true;
    go.textContent = !s || !name ? 'Enter a symbol and a name' : st.kind === 'token' && !(supply() >= 1) ? 'Enter how many will exist' : 'Reading the price…';
    if (!s) { $('crFacts').innerHTML = ''; return; }
    const mine = ++asked;
    if (!S.wallet && !(await learn())) { $('crFacts').innerHTML = connectNote('to read the chain\'s creation price and create this'); go.textContent = 'Connect your wallet to create'; return; }
    try {
      // ONE read: the price of this creation including its picture (the price counts the picture's started kilobytes)
      const f = await dex.createFee(s, st.kind, st.art ? st.art.length : 0);
      if (mine !== asked) return;
      st.fee = Number(f && f.fee_atomic) / dex.UNIT;
      $('crFacts').innerHTML = '<span>Creation price, set by the chain</span><b>' + usd(st.fee) + '</b>' +
        (st.art ? '<span>Its picture</span><b>' + (st.art.length / 1024).toFixed(1) + ' KB, kept on the chain (included in the price)</b>' : '') +
        '<span>Supply</span><b>' + (st.kind === 'nft' ? 'one, the only one' : supply() >= 1 ? supply().toLocaleString('en-US') + ' ' + esc(s) : '—') + '</b>';
      if (ready) { go.disabled = false; go.textContent = st.kind === 'nft' ? 'Make the NFT' : 'Launch ' + s; }
    } catch (e) { if (mine === asked) { go.textContent = 'Could not read the price'; $('crMsg').innerHTML = '<div class="note bad">' + esc(dex.errText(e)) + '</div>'; } }
  };
  let wait = 0;
  const later = () => { $('crMsg').innerHTML = ''; clearTimeout(wait); wait = setTimeout(paint, 300); };
  ['crSym', 'crName', 'crSupply'].forEach((id) => $(id).addEventListener('input', later));
  $('crLogo').addEventListener('change', async (ev) => {
    const f = ev.target.files && ev.target.files[0];
    if (!f) return;
    try { st.art = await gen.bytesOf(await gen.ownArt(f), gen.TOKEN_ART_MOST); $('crDropT').textContent = 'Picture added (' + (st.art.length / 1024).toFixed(1) + ' KB). Choose another'; later(); /* the price includes the picture: read it again */ }
    catch (e) { st.art = null; $('crMsg').innerHTML = '<div class="note bad">' + esc(dex.errText(e)) + '</div>'; }
  });

  $('crGo').addEventListener('click', async () => {
    if (st.busy) return;
    st.busy = true;
    const go = $('crGo');
    go.disabled = true;
    go.textContent = 'Confirm in your wallet…';
    try {
      const made = await dex.create({ kind: 'token', symbol: sym(), name: $('crName').value.trim(), supply: supply(), artHex: st.art ? gen.toHex(st.art) : undefined });
      // keep the card with its picture on this device, so the token shows its own picture here
      if (made.card && st.art) { try { const c = await dex.addCard(made.card); await store.keep({ tag: c.tag, card: c.card, symbol: c.symbol, name: c.name, kind: c.kind, art_hex: c.art_hex, art_mime: c.art_mime }); } catch (_) { /* the token exists all the same */ } }
      const tag = String(made.asset_tag_hex || '').toLowerCase();
      const done = $('crDone');
      done.innerHTML = '<div class="card glow stack"><div class="eyebrow">Created</div><h2>' + esc(sym()) + ' is yours</h2>' +
        '<p class="muted">' + (st.kind === 'nft' ? 'The one and only is on its way to your wallet.' : 'The whole supply is on its way to your wallet.') + ' It shows up within a block or two, and the chain itself records its name' + (st.art ? ' and picture' : '') + ', so anyone can find it by its id. Its card, if you want to hand it to someone directly:</p>' +
        '<div class="cardtext">' + esc(made.card || '') + '</div><div class="btns" id="crBtns"></div></div>';
      const btns = done.querySelector('#crBtns');
      if (made.card) btns.appendChild(dex.copyButton(made.card, 'Copy the card'));
      const a = document.createElement('a');
      a.className = 'ghost';
      a.href = (st.kind === 'nft' ? '#/nfts?t=' : '#/token?t=') + tag;
      a.textContent = st.kind === 'nft' ? 'Open my NFTs' : 'Open its market';
      btns.appendChild(a);
      done.scrollIntoView({ behavior: 'smooth', block: 'center' });
      go.textContent = 'Created';
    } catch (e) {
      $('crMsg').innerHTML = '<div class="note bad">' + esc(dex.errText(e)) + '</div>';
      st.busy = false;
      paint();
      return;
    }
    st.busy = false;
  });
  paint();
  tiers();
}
