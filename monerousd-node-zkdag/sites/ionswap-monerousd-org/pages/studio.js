// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// pages/studio.js — the NFT studio (2026-11-10): turn ONE photo into a whole collection, or bring your own artwork.
//
// The photo is drawn on this device and never leaves it (lib/artgen.js). Each piece becomes a real NFT on the chain:
// one unit that exists once, with its picture's digest bound into its identity, so the picture a buyer is shown is
// provably the piece's own. The wallet that frames this page asks ONCE for the whole collection, states the count and
// the price in dollars in its own sheet, and makes the pieces one after another.
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. Its second party is the wallet that frames it; the creation path
// is exercised with the real wallet and real nodes (scratchpad/net/nft.py), never inside this file.
import { S, learn, ask, esc, usd, hiddenNote, isHidden } from '../lib/native.js';
import { paint } from '../lib/paint.js';
import * as dex from '../lib/dex.js';
import * as gen from '../lib/artgen.js';
import * as store from '../lib/artstore.js';
import * as market from '../lib/market.js';

const COUNTS = [6, 12, 24, 48];
const IDEAS = ['neon cyberpunk', 'gold and luxury', 'retro pixel arcade', 'ink sketch on paper', 'pastel and soft', 'dark and moody', 'vaporwave', 'holographic'];

export default async function render(view /* , ctx */) {
  const root = document.createElement('section');
  root.className = 'ion page';
  const st = { mode: 'photo', photo: null, files: [], count: 12, seed: gen.seedNow(), pieces: [], open: null, busy: false, each: null, kb: 0, handleTouched: false };
  root.innerHTML = '<div><div class="eyebrow">NFT studio</div><h1>One photo in, a <em>collection</em> out</h1>' +
    '<p class="lead">Drop a picture. The studio redraws it in different art styles, palettes, frames and effects, makes a few of them truly rare, and turns every piece into a real NFT. Your photo never leaves this device.</p></div>' +
    '<div class="two"><div class="card glow stack">' +
      '<div class="seg"><button type="button" data-mode="photo" class="on">From one photo</button><button type="button" data-mode="own">My own artwork</button></div>' +
      '<label class="drop" id="stDrop"><input type="file" id="stFile" accept="image/png,image/jpeg,image/webp" hidden /><b id="stDropT">Choose a photo</b><span id="stDropS">or drop one here · PNG, JPEG or WebP</span></label>' +
      '<label class="lab">Collection name<input class="field" id="stName" maxlength="60" placeholder="Night Owls" autocomplete="off" /></label>' +
      '<label class="lab">Its handle in the marketplace<input class="field" id="stHandle" maxlength="32" placeholder="night-owls" autocapitalize="off" autocomplete="off" spellcheck="false" /></label>' +
      '<label class="lab">About it (optional)<textarea class="field" id="stText" maxlength="300" placeholder="A line or two people see on the collection\'s page"></textarea></label>' +
      '<label class="lab">Symbol, letters and digits<input class="field" id="stSym" maxlength="8" placeholder="OWL" autocapitalize="characters" autocomplete="off" spellcheck="false" /></label>' +
      '<div id="stPhotoOnly" class="stack">' +
        '<div class="lab">How many pieces<div class="seg" id="stCounts">' + COUNTS.map((c) => '<button type="button" data-count="' + c + '">' + c + '</button>').join('') + '</div></div>' +
        '<label class="lab">Describe what you want (optional)<textarea class="field" id="stWant" maxlength="300" placeholder="neon cyberpunk, no frame, lots of glitch"></textarea></label>' +
        '<div class="btns" id="stIdeas">' + IDEAS.map((i) => '<button type="button" class="ghost" data-idea="' + esc(i) + '">' + esc(i) + '</button>').join('') + '</div>' +
      '</div>' +
      '<div class="btns"><button class="cta" id="stMake" type="button" disabled>Choose a photo first</button></div><div id="stMsg"></div></div>' +
    '<div class="stack"><div class="card stack" id="stSide"><h2>What makes a piece rare</h2><div class="kv" id="stTiers"></div>' +
      '<p class="muted">Every piece carries four traits: a style, a palette, a frame and an effect. A collection holds a fixed, small number of pieces from the rare tiers, and no two pieces share all four traits.</p></div></div></div>' +
    '<div class="card stack" id="stResult" hidden><div class="row"><h2 id="stTitle"></h2><div class="btns"><button class="ghost" id="stShuffle" type="button">Shuffle</button></div></div>' +
      '<div class="tiles" id="stGrid"></div><div class="kv" id="stCost"></div><button class="cta" id="stCreate" type="button" disabled>Create the collection</button><div id="stProgress"></div></div>';
  view.appendChild(root);
  const $ = (id) => root.querySelector('#' + id);
  const say = (el, kind, text) => { el.innerHTML = text ? '<div class="note ' + kind + '">' + esc(text) + '</div>' : ''; };
  $('stTiers').innerHTML = gen.TIERS.map((t, i) => '<span><i class="tier" style="background:' + gen.TIER_COLOR[i] + '"></i>' + t + '</span><b>' + ['most pieces', 'about 1 in 4', 'about 1 in 7', 'about 1 in 17', 'about 1 in 50'][i] + '</b>').join('');

  const sym = () => $('stSym').value.replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 8);
  // every piece's symbol is the collection's symbol and its number
  const symOf = (n, total) => { const s = sym() || 'NFT', width = Math.max(String(total).length, 3); return s + String(n).padStart(width, '0'); };
  const nameOf = (n) => (($('stName').value.trim() || 'Untitled') + ' #' + n).slice(0, 128);

  const ready = () => {
    const have = st.mode === 'photo' ? !!st.photo : st.files.length > 0;
    const b = $('stMake');
    b.disabled = !have || st.busy;
    b.textContent = st.busy ? 'Drawing…' : !have ? (st.mode === 'photo' ? 'Choose a photo first' : 'Choose your artwork first') : st.mode === 'photo' ? 'Generate ' + st.count + ' pieces' : 'Use ' + st.files.length + ' file' + (st.files.length === 1 ? '' : 's');
    root.querySelectorAll('[data-count]').forEach((x) => x.classList.toggle('on', Number(x.dataset.count) === st.count));
    root.querySelectorAll('[data-mode]').forEach((x) => x.classList.toggle('on', x.dataset.mode === st.mode));
    $('stPhotoOnly').hidden = st.mode !== 'photo';
    $('stFile').multiple = st.mode === 'own';
    $('stDropT').textContent = st.mode === 'photo' ? (st.photo ? 'Photo loaded. Choose another' : 'Choose a photo') : st.files.length ? st.files.length + ' file(s) chosen. Choose others' : 'Choose your artwork';
    $('stDropS').textContent = st.mode === 'photo' ? 'or drop one here · PNG, JPEG or WebP' : 'one file for each NFT · PNG, JPEG or WebP';
  };

  async function take(files) {
    const list = Array.from(files || []).filter((f) => /^image\/(png|jpeg|webp)$/.test(f.type));
    if (!list.length) { say($('stMsg'), 'bad', 'Choose a PNG, JPEG or WebP picture.'); return; }
    say($('stMsg'), '', '');
    try {
      if (st.mode === 'photo') st.photo = await gen.loadPhoto(list[0]); else st.files = list;
    } catch (e) { say($('stMsg'), 'bad', dex.errText(e)); }
    ready();
  }
  $('stFile').addEventListener('change', (ev) => take(ev.target.files));
  const drop = $('stDrop');
  ['dragenter', 'dragover'].forEach((n) => drop.addEventListener(n, (ev) => { ev.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((n) => drop.addEventListener(n, (ev) => { ev.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (ev) => take(ev.dataTransfer && ev.dataTransfer.files));
  root.querySelectorAll('[data-mode]').forEach((b) => b.addEventListener('click', () => { st.mode = b.dataset.mode; ready(); }));
  root.querySelectorAll('[data-count]').forEach((b) => b.addEventListener('click', () => { st.count = Number(b.dataset.count); ready(); }));
  root.querySelectorAll('[data-idea]').forEach((b) => b.addEventListener('click', () => { const w = $('stWant'); w.value = (w.value.trim() ? w.value.trim() + ', ' : '') + b.dataset.idea; }));
  ['stName', 'stSym'].forEach((id) => $(id).addEventListener('input', () => { if (st.pieces.length) paintGrid(); }));
  // the handle follows the name until the person types their own; it is always shown as the chain will keep it
  $('stName').addEventListener('input', () => { if (!st.handleTouched) $('stHandle').value = market.canonHandle($('stName').value); });
  $('stHandle').addEventListener('input', () => { st.handleTouched = true; $('stHandle').value = market.canonHandle($('stHandle').value); });

  // one piece: its canvas, its bytes, its traits
  function tile(p, i) {
    const total = st.pieces.length;
    return '<button type="button" class="tile' + (st.open === i ? ' on' : '') + '" data-piece="' + i + '"><div class="art pic" style="--tier:' + gen.TIER_COLOR[p.tier] + '"><img alt="" src="' + p.url + '" /></div>' +
      '<b>' + esc(nameOf(p.n)) + '</b><span class="muted"><i class="tier" style="background:' + gen.TIER_COLOR[p.tier] + '"></i>' + gen.TIERS[p.tier] + ' · ' + esc(symOf(p.n, total)) + '</span></button>';
  }
  function paintGrid() {
    const total = st.pieces.length;
    $('stResult').hidden = !total;
    if (!total) return;
    $('stTitle').textContent = ($('stName').value.trim() || 'Untitled') + ' · ' + total + ' piece' + (total === 1 ? '' : 's');
    $('stShuffle').hidden = st.mode !== 'photo';
    $('stGrid').innerHTML = st.pieces.map(tile).join('');
    $('stGrid').querySelectorAll('[data-piece]').forEach((b) => b.addEventListener('click', () => { st.open = Number(b.dataset.piece); paintGrid(); paintSide(); }));
    const counts = gen.TIERS.map((_, t) => st.pieces.filter((p) => p.tier === t).length);
    $('stCost').innerHTML = '<span>Pieces by rarity</span><b>' + counts.map((c, t) => (c ? c + ' ' + gen.TIERS[t].toLowerCase() : '')).filter(Boolean).join(' · ') + '</b>' +
      '<span>Creation price, set by the chain</span><b>' + (st.each == null ? 'reading…' : usd(priceOfAll()) + ' for ' + total + (total === 1 ? ' piece' : ' pieces')) + '</b>' +
      '<span>Each picture</span><b>kept on the chain, so it shows in every wallet and in the marketplace</b>' +
      '<span>The collection\'s page</span><b>your wallet prices it in its own sheet before you confirm</b>' +
      '<span>Who holds them</span><b>you: each arrives in your wallet</b>';
    const b = $('stCreate');
    // with no wallet answering, this same button connects one (the page's own handler below does nothing until then)
    b.disabled = S.wallet ? st.busy || st.each == null : false;
    if (S.wallet) delete b.dataset.connect; else b.dataset.connect = '1';
    b.textContent = !S.wallet ? 'Connect wallet to create' : 'Create ' + total + ' NFT' + (total === 1 ? '' : 's');
  }
  function paintSide() {
    const p = st.pieces[st.open];
    if (!p) return;
    const rows = p.traits ? Object.entries(p.traits).map(([k, o]) => '<span>' + esc(k) + '</span><b><i class="tier" style="background:' + gen.TIER_COLOR[o.tier] + '"></i>' + esc(o.name) + ' · ' + p.share[k] + ' of ' + st.pieces.length + '</b>').join('') : '<span>Artwork</span><b>your own file</b>';
    $('stSide').innerHTML = '<div class="art pic big" style="--tier:' + gen.TIER_COLOR[p.tier] + '"><img alt="" src="' + p.url + '" /></div><h2>' + esc(nameOf(p.n)) + '</h2><div class="kv">' + rows +
      '<span>Rarity</span><b>' + gen.TIERS[p.tier] + '</b><span>Picture</span><b>' + (p.bytes.length / 1024).toFixed(1) + ' KB, bound into the NFT</b></div>' +
      '<div class="btns"><a class="ghost" style="text-decoration:none" download="' + esc(symOf(p.n, st.pieces.length)) + '.webp" href="' + p.url + '">Save the picture</a><button class="ghost" id="stDropPiece" type="button">Leave this one out</button></div>';
    $('stDropPiece').addEventListener('click', () => { URL.revokeObjectURL(p.url); st.pieces.splice(st.open, 1); st.open = null; paintGrid(); });
  }

  // the chain's price for all the pieces: an NFT's own price, plus one kilobyte price for each started kilobyte of its
  // picture (both read from the chain through the wallet's node)
  const priceOfAll = () => st.pieces.reduce((sum, p) => sum + st.each + st.kb * Math.ceil(p.bytes.length / 1024), 0);
  async function price() {
    st.each = null;
    if (!S.wallet && !(await learn())) return;
    try {
      const f = await dex.createFee(symOf(1, Math.max(1, st.pieces.length)), 'nft', 0);
      st.each = Number(f && f.fee_atomic) / dex.UNIT;
      st.kb = Number((f && f.picture_kb_fee_atomic) || 0) / dex.UNIT;
      if (!isFinite(st.each) || !isFinite(st.kb)) st.each = null;
    } catch (_) { st.each = null; }
    paintGrid();
  }

  async function make(newSeed) {
    if (st.busy) return;
    st.busy = true; ready();
    if (newSeed) st.seed = gen.seedNow();
    for (const p of st.pieces) URL.revokeObjectURL(p.url);
    st.pieces = []; st.open = null;
    try {
      if (st.mode === 'photo') {
        const made = gen.plan(st.count, st.seed, $('stWant').value);
        for (const item of made.items) {
          const bytes = await gen.bytesOf(gen.draw(st.photo, item));
          st.pieces.push({ ...item, bytes, url: URL.createObjectURL(new Blob([bytes])) });
          $('stMake').textContent = 'Drawing ' + st.pieces.length + ' of ' + made.items.length + '…';
          // let the page breathe between pieces (a message, not a timer: a timer is slowed to one a second
          // whenever the page is not in front, and a 48-piece collection would then take a minute)
          await new Promise((r) => { const ch = new MessageChannel(); ch.port1.onmessage = r; ch.port2.postMessage(0); });
        }
        say($('stMsg'), 'ok', made.asked ? 'Made to your description. Shuffle for another take on it.' : 'Made. Describe what you want to steer it, or shuffle for another take.');
      } else {
        let n = 0;
        for (const f of st.files) {
          const bytes = await gen.bytesOf(await gen.ownArt(f));
          st.pieces.push({ n: ++n, tier: 0, traits: null, share: {}, bytes, url: URL.createObjectURL(new Blob([bytes])) });
        }
        say($('stMsg'), 'ok', 'Ready. Each file becomes one NFT, shown as its centre square.');
      }
    } catch (e) { say($('stMsg'), 'bad', dex.errText(e)); }
    st.busy = false; ready(); paintGrid(); price();
    if (st.pieces.length) $('stResult').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  $('stMake').addEventListener('click', () => make(false));
  $('stShuffle').addEventListener('click', () => make(true));

  // create: the wallet asks once; this page watches the wallet make them
  $('stCreate').addEventListener('click', async () => {
    if (!S.wallet) return; // the press connects a wallet (app.js handles `data-connect`)
    if (st.busy || !st.pieces.length) return;
    if (!sym() || !$('stName').value.trim()) { say($('stProgress'), 'bad', 'Give the collection a name and a symbol first.'); return; }
    const handle = market.canonHandle($('stHandle').value || $('stName').value);
    if (!handle) { say($('stProgress'), 'bad', 'Give the collection a handle: letters, digits, - and _.'); return; }
    st.busy = true; paintGrid();
    const total = st.pieces.length;
    const items = st.pieces.map((p) => ({ symbol: symOf(p.n, total), name: nameOf(p.n), artHex: gen.toHex(p.bytes) }));
    try {
      // every piece's card is worked out and kept BEFORE anything is created, so a piece that arrives while this
      // page is closed still has its name and its picture here
      say($('stProgress'), '', 'Preparing the pieces…');
      for (const it of items) {
        const c = await ask('cardFor', { kind: 'nft', symbol: it.symbol, name: it.name, artHex: it.artHex }, 25000);
        await store.keep({ tag: c.tag_hex, card: c.card, symbol: c.symbol, name: c.name, kind: 'nft', art_hex: c.art_hex, art_mime: c.art_mime });
      }
      say($('stProgress'), '', 'Confirm in your wallet…');
      // the collection itself goes on the chain first (its handle, title, words and the first piece as its cover), then
      // each piece is filed under it; the wallet shows the whole price in dollars and asks once
      await ask('createCollection', { items, handle, title: $('stName').value.trim().slice(0, 64), text: $('stText').value.trim(), coverHex: items[0].artHex }, 240000);
      watch(total);
    } catch (e) { say($('stProgress'), 'bad', dex.errText(e)); st.busy = false; paintGrid(); }
  });
  function watch(total) {
    const tick = async () => {
      if (!root.isConnected) return;
      try {
        const p = await ask('collectionProgress', {}, 25000);
        const made = (p.made || []).length, failed = (p.failed || []).length;
        // read again every three seconds and repainted in place (`paint`): the progress card does not rise in again
        // with every read (it flickered, the same cause as the Activity page's cards)
        paint($('stProgress'), ['<div class="item"><div class="t">' + (p.running ? 'Making ' + esc(p.now || 'the next piece') : 'Finished') + '</div><span class="chip ' + (p.running ? 'live' : 'done') + '">' + made + ' of ' + total + ' made</span>' +
          '<div class="s">' + (p.running ? 'Keep the wallet open. Each piece takes about a block; closing the wallet makes no more and loses none.' : failed ? failed + ' could not be made: ' + esc(String(p.failed[0].error || '').slice(0, 160)) + ' Nothing was paid for those.' : 'Every piece is in your wallet or arriving in the next blocks.') + '</div>' +
          '<div class="bar"><i style="--p:' + Math.round((made / total) * 100) + '%"></i></div></div>'].concat(p.running ? [] : ['<a class="ghost" href="#/nfts" style="text-align:center;text-decoration:none">Open my NFTs</a>', '<a class="ghost" href="#/market?c=' + encodeURIComponent(market.canonHandle($('stHandle').value || $('stName').value)) + '" style="text-align:center;text-decoration:none">See it in the marketplace</a>']));
        if (p.running) setTimeout(tick, 3000); else { st.busy = false; paintGrid(); }
      } catch (e) {
        // hidden from this site: the wallet is still making them, and shows the progress itself
        if (isHidden(e)) $('stProgress').innerHTML = '<div class="note">Your wallet is making them now and shows each one as it arrives.</div>' + hiddenNote('holdings and progress');
        else say($('stProgress'), 'bad', dex.errText(e));
        st.busy = false; paintGrid();
      }
    };
    tick();
  }
  if (!S.wallet) learn().then(() => { paintGrid(); });
  ready();
}
