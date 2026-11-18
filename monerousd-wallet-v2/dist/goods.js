// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// Goods and services, for someone who is not technical:
//
//   SELLING  (Merchant page)  type what it is and the price, press Create sale, send the link. Nothing else.
//   BUYING   (Pay page)       paste or open the link, read one sentence, press Pay.
//   WAITING  (Wallet page)    money being held for a purchase shows there with one button: "I have it".
//
// The two wallets talk to each other by themselves (`sale_sync` in the wallet core); nobody copies a code unless a
// wallet was closed in between. Every button calls one wallet-core command and this file holds no money logic. The
// core asks for Touch ID with the one sentence that says what will happen, before anything is spent.
//
// TWO-PARTY-REVIEWED: page code, not a test; it builds no endpoint. A purchase's two wallets are checked on real
// nodes by scratchpad/net/goods.py.
'use strict';

const goods = { offer: null, how: 'held', link: '', until: 0 };

function gEl(id) { return document.getElementById(id); }
function gSay(id, text, bad) { const e = gEl(id); if (e) { e.textContent = text || ''; e.classList.toggle('err', !!bad); } }
function gWhy(e) { return String((e && (e.message || e)) || 'Something went wrong.'); }
function gUsd(atomic) { return '$' + (Number(atomic) / 1e8).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 8 }); }
function gWhen(ms) { return new Date(Number(ms)).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }); }
function gNode(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }
async function gCopy(text) { try { await navigator.clipboard.writeText(text); return true; } catch (_) { return false; } }
function gSize(bytes) { const n = Number(bytes) || 0; return n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : (n >= 1024 ? Math.ceil(n / 1024) + ' KB' : n + ' bytes'); }
// A file the owner picked, as the base64 the wallet core takes.
function gFileBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).slice(String(r.result).indexOf(',') + 1));
    r.onerror = () => reject(new Error('The file could not be read.'));
    r.readAsDataURL(file);
  });
}
const isLink = (t) => /^monerousd:(pay|sale)\?/.exec(String(t || '').trim()) !== null;
const isSale = (t) => String(t || '').trim().startsWith('monerousd:sale?');

// ── BUYING: a shop's or a seller's link, paid from the Pay box ──────────────────────────────────────────────
// The "Pay to" box takes a @name, an address or a link. With a link in it the amount is the link's own, so the
// amount box steps aside and the link is read before anything is paid.
function goodsToChanged() {
  const link = isLink(gEl('sendTo').value);
  const panel = gEl('payPanel');
  if (panel) panel.classList.toggle('paying-link', link);
  if (!link) { goods.offer = null; gEl('goodsOfferBox').style.display = 'none'; gSay('goodsLinkStatus', ''); return; }
  // a link is read as soon as it is in the box: there is no second button to find
  clearTimeout(goods.reading);
  if (!goods.offer || goods.offer.link !== gEl('sendTo').value.trim()) goods.reading = setTimeout(() => goodsReviewLink(), 300);
}

async function goodsReviewLink(link) {
  goods.offer = null;
  gEl('goodsOfferBox').style.display = 'none';
  const text = String(link || gEl('sendTo').value || '').trim();
  if (!isLink(text)) { gSay('goodsLinkStatus', 'That is not a payment link.', true); return; }
  gEl('sendTo').value = text;
  const panel = gEl('payPanel');
  if (panel) panel.classList.add('paying-link');
  gSay('goodsLinkStatus', isSale(text) ? 'Reading the sale…' : 'Asking the shop over the private network…');
  try {
    const offer = await walletCore(isSale(text) ? 'sale_read' : 'checkout_offer', { link: text });
    goods.offer = { link: text, offer };
    gEl('goodsOfferSentence').textContent = offer.sentence;
    gEl('goodsOfferBox').style.display = '';
    // a person's protected sale: the buyer may pick up at a relay
    const relay = gEl('goodsRelay');
    if (relay) { relay.hidden = !(isSale(text) && offer.mode === 'protected'); relay.value = ''; }
    const open = offer.status === 'open' || offer.status === 'accepted';
    gEl('btnGoodsPay').disabled = !open;
    gSay('goodsLinkStatus', open ? '' : 'This order is no longer waiting for a payment.', !open);
  } catch (e) { gSay('goodsLinkStatus', gWhy(e), true); }
}

async function goodsPayLink() {
  if (!goods.offer) return;
  const link = goods.offer.link;
  const wasDownload = goods.offer.offer && goods.offer.offer.mode === 'download';
  gEl('btnGoodsPay').disabled = true;
  gSay('goodsLinkStatus', 'Paying…');
  try {
    const relay = isSale(link) && gEl('goodsRelay') ? gEl('goodsRelay').value.trim() : '';
    const done = await walletCore(isSale(link) ? 'sale_buy' : 'checkout_pay', isSale(link) ? { link, relay: relay || null } : { link });
    gEl('goodsOfferBox').style.display = 'none';
    gEl('sendTo').value = '';
    goods.offer = null;
    goodsToChanged();
    gSay('goodsLinkStatus', wasDownload
      ? 'Order sent. Keep the wallet open until your file arrives: it is saved to your Downloads folder as soon as the seller\'s wallet releases it, usually within a minute.'
      : done.waiting_for_seller
      ? 'Order sent. Your payment goes into escrow once the seller\'s wallet confirms; track it on your Wallet page.'
      : (done.mode === 'protected'
        ? 'Payment in escrow. When your order arrives, tap Confirm receipt on your Wallet page.'
        : 'Paid. This payment is final.'));
    goodsWatch();
  } catch (e) { gSay('goodsLinkStatus', gWhy(e) + ' Nothing was paid.', true); gEl('btnGoodsPay').disabled = false; }
}

// A payment link opened anywhere on this device lands on the Pay page, already read and waiting for one tap.
function goodsOpenLink(link) {
  if (typeof switchView === 'function') switchView('send');
  if (typeof setSendMode === 'function') setSendMode('pay');
  if (window.mobileLayout) window.mobileLayout.open('send', 'Pay');
  goodsReviewLink(link);
}

// ── one purchase or sale, as a row ──────────────────────────────────────────────────────────────────────────
// `field` (optional) is a quiet code box for the rare case the wallets could not talk: { summary, placeholder, label, run }.
function gRow(p, buttons, field) {
  const row = gNode('div', 'goods-row' + (p.locked ? (p.deadline_passed ? ' late' : ' held') : ''));
  const head = gNode('div', 'goods-row-head');
  head.append(gNode('b', null, p.title || 'Purchase'), gNode('span', 'goods-row-amt', p.amountText != null ? p.amountText : gUsd(p.amount)));
  const meta = gNode('div', 'goods-row-meta');
  meta.append(gNode('span', 'mx-pill ' + (p.pill || ''), p.status), gNode('span', null, p.when || ''));
  const say = gNode('div', 'goods-row-say');
  const guard = (b, run) => async () => {
    b.disabled = true;
    try { const out = await run(); if (typeof out === 'string') say.textContent = out; } catch (e) { say.textContent = gWhy(e); }
    b.disabled = false;
  };
  row.append(head, meta);
  if (buttons.length) {
    const acts = gNode('div', 'goods-row-acts');
    for (const [label, run, primary] of buttons) {
      const b = gNode('button', 'btn ' + (primary ? 'btn-primary' : 'btn-ghost'), label);
      b.addEventListener('click', guard(b, run));
      acts.appendChild(b);
    }
    row.appendChild(acts);
  }
  // one quiet box per field; a field with `file` takes a file the owner picks instead of typed text
  for (const one of (Array.isArray(field) ? field : (field ? [field] : []))) {
    const more = gNode('details', 'goods-row-more');
    more.appendChild(gNode('summary', null, one.summary));
    const line = gNode('div', 'goods-row-code');
    const input = gNode('input');
    if (one.file) { input.setAttribute('type', 'file'); input.setAttribute('accept', one.file); }
    else { input.setAttribute('placeholder', one.placeholder); input.setAttribute('autocomplete', 'off'); input.setAttribute('spellcheck', 'false'); }
    const go = gNode('button', 'btn btn-ghost', one.label);
    go.addEventListener('click', guard(go, () => one.run(one.file ? input.files[0] : input.value.trim())));
    line.append(input, go);
    more.appendChild(line);
    row.appendChild(more);
  }
  row.appendChild(say);
  return row;
}

// One row per purchase. A purchase held from several of the buyer's notes is several parts underneath; the buyer sees
// one row with the whole price, and every action acts on all of its parts.
async function gList(role) {
  const all = await walletCore('purchase_list');
  const rows = (all.purchases || []).filter((p) => p.role === role);
  let groups = {};
  if (role === 'buyer') { try { groups = await walletCore('sale_groups'); } catch (_) { groups = {}; } }
  const byKey = new Map();
  for (const p of rows.filter((r) => r.kind !== 'bond')) {
    const key = groups[p.id] || p.id;
    const g = byKey.get(key);
    if (!g) { byKey.set(key, Object.assign({}, p, { ids: [p.id], bonds: [] })); continue; }
    g.amount = Number(g.amount) + Number(p.amount);
    g.locked = g.locked && p.locked;
    g.deadline_passed = g.deadline_passed && p.deadline_passed;
    g.ids.push(p.id);
  }
  // a bond is never part of the price: it rides its purchase's row, or stands alone when this wallet posted it
  for (const p of rows.filter((r) => r.kind === 'bond')) {
    const g = byKey.get(groups[p.id] || '');
    if (g) g.bonds.push(p); else byKey.set(p.id, Object.assign({}, p, { ids: [p.id], bonds: [] }));
  }
  return [...byKey.values()];
}

// What a purchase's bonds add to its row: "seller bond $5.00 locked".
function gBondNote(p) {
  return (p.bonds || []).map((b) => ' · bond ' + gUsd(b.amount) + (b.locked ? ' locked' : ' pending')).join('');
}

// ── WAITING: money held for this wallet's purchases, on the Wallet page ─────────────────────────────────────
async function renderPurchases() {
  const card = gEl('heldCard');
  const box = gEl('goodsPurchases');
  if (!card || !box) return;
  let mine = [];
  let files = [];
  try { mine = await gList('buyer'); } catch (_) { mine = []; }
  try { files = (await walletCore('sale_downloads')).downloads || []; } catch (_) { files = []; }
  card.hidden = mine.length === 0 && files.length === 0;
  box.textContent = '';
  // a download that arrived: it is written to the Downloads folder by itself, and this row says where
  for (const d of files) {
    const where = d.saved ? String(d.saved).split(/[\\/]/).slice(-2).join(' / ') : d.name;
    const view = { title: d.title || d.name, amountText: gSize(d.bytes), locked: true, deadline_passed: false,
      status: d.saved ? 'Download saved' : 'Download ready', pill: 'good', when: where };
    box.appendChild(gRow(view, d.saved
      ? [['Done', async () => { await walletCore('sale_download_saved', { id: d.id }); renderPurchases(); }]]
      : [['Save file', async () => { const out = await walletCore('sale_download', { id: d.id }); renderPurchases(); return 'Saved: ' + out.saved; }, true]], null));
  }
  // tracking numbers sellers have named and this wallet's owner has not accepted (only when this version accepts a carrier)
  let named = {};
  try { for (const o of ((await walletCore('sale_tracking_offers')).offers || [])) named[o.id] = o.tracking; } catch (_) { named = {}; }
  for (const p of mine) {
    const view = Object.assign({}, p, p.locked
      ? { status: p.deadline_passed ? 'Refund available' : 'In escrow', pill: p.deadline_passed ? 'warn' : 'good', when: (p.deadline_passed ? 'since ' : 'refundable after ') + gWhen(p.deadline_ms) + gBondNote(p) }
      : { status: 'Awaiting seller', pill: '', when: '' });
    if (p.kind === 'bond') continue; // a bond with no purchase on this page is not this wallet's to act on
    const bondIds = (p.bonds || []).map((b) => b.id);
    const buttons = [];
    let field = null;
    if (p.kind === 'sub') {
      view.status = p.locked ? (p.deadline_passed ? 'Paid' : 'Subscription active') : 'Subscription pending';
      view.pill = p.locked ? 'good' : '';
      view.when = p.deadline_passed ? 'current period' : 'next billing ' + gWhen(p.deadline_ms);
      buttons.push(['Cancel subscription', async () => {
        const out = await walletCore('sale_cancel', { id: p.id });
        goodsWatch();
        return out.returned ? 'Subscription cancelled. The next payment is refunded to you.' : 'Subscription cancelled. No further payments; the current period stays paid.';
      }]);
      box.appendChild(gRow(view, buttons, null));
      continue;
    }
    if (p.kind === 'key') {
      // a download: the seller's wallet takes the payment by releasing the file's key; there is nothing to confirm
      view.status = p.locked ? (p.deadline_passed ? 'Refund available' : 'Paid') : 'Awaiting seller';
      view.pill = p.locked ? (p.deadline_passed ? 'warn' : 'good') : '';
      view.when = p.locked ? (p.deadline_passed ? 'the file was not released in time' : 'keep the wallet open: your file arrives automatically; refundable after ' + gWhen(p.deadline_ms)) : '';
      if (p.locked && p.deadline_passed) buttons.push(['Claim refund', async () => {
        for (const id of p.ids) await walletCore('purchase_reclaim', { id });
        goodsWatch();
        return 'Refund sent to your wallet.';
      }, true]);
      box.appendChild(gRow(view, buttons, null));
      continue;
    }
    // THE BUYER accepts a tracking number; a seller's word alone never pins a parcel. The wallet core asks first, in
    // plain words: accept only if the carrier's own page shows the parcel going to your address.
    const offered = (p.ids || [p.id]).map((id) => named[id]).find(Boolean);
    if (p.locked && offered) {
      view.when = 'the seller shipped parcel ' + offered + ' · ' + view.when;
      buttons.push(['Accept tracking', async () => {
        const id = (p.ids || [p.id]).find((x) => named[x]);
        const out = await walletCore('sale_accept_tracking', { id });
        goodsWatch();
        return 'Parcel ' + out.tracking + ' accepted. When the carrier reports it delivered, your payment is released automatically.';
      }]);
    }
    if (p.locked) {
      buttons.push(['Confirm receipt', async () => {
        try { await walletCore('sale_i_have_it', { id: p.id }); goodsWatch(); return 'Receipt confirmed. Payment released to the seller.'; } catch (_) { /* a shop, or a closed wallet */ }
        try { await walletCore('checkout_hand_over', { id: p.id }); goodsWatch(); return 'Receipt confirmed. Payment released to the shop.'; } catch (_) { /* show the code */ }
        const codes = [];
        for (const id of p.ids.concat(bondIds)) codes.push(await walletCore('purchase_code', { id }));
        await gCopy(codes.join(' '));
        return 'Release code for the seller: ' + codes.join(' ');
      }, true]);
      if (p.deadline_passed) buttons.push(['Claim refund', async () => {
        for (const id of p.ids) await walletCore('purchase_reclaim', { id });
        // the seller's delivery bond is this wallet's too; a relay's custody bond is the seller's and is left alone
        let bond = 0;
        for (const b of p.bonds || []) { try { await walletCore('purchase_reclaim', { id: b.id }); bond += Number(b.amount); } catch (_) { /* not this wallet's, or never posted */ } }
        goodsWatch();
        return 'Refund sent to your wallet.' + (bond ? ' The seller\'s bond of ' + gUsd(bond) + ' is yours as well.' : '');
      }]);
      field = { summary: 'Enter a refund code', placeholder: 'Refund code', label: 'Claim refund', run: async (code) => {
        if (!code) return 'Enter the refund code from the seller.';
        for (const one of code.split(/\s+/)) await walletCore('purchase_refund', { code: one });
        goodsWatch();
        return 'Refund sent to your wallet.';
      } };
      // a shop that called the sale off answers with its refund code, and the money comes back by itself
      walletCore('checkout_status', { id: p.id }).then((s) => { if (s && s.refunded) renderPurchases(); }).catch(() => {});
    }
    box.appendChild(gRow(view, buttons, field));
  }
}

// ── SELLING: the Merchant page ─────────────────────────────────────────────────────────────────────────────
function mxHow(how) {
  goods.how = how;
  for (const b of document.querySelectorAll('.mx-opt')) {
    const on = b.dataset.how === how;
    b.classList.toggle('active', on);
    b.setAttribute('aria-checked', on ? 'true' : 'false');
  }
  const days = gEl('mxDaysRow');
  if (days) days.hidden = how !== 'held';
  const more = gEl('mxMore');
  if (more) more.hidden = how !== 'held';
  const every = gEl('mxEveryRow');
  if (every) every.hidden = how !== 'every';
  const file = gEl('mxFileRow');
  if (file) file.hidden = how !== 'file';
  // a phone shows the option names only, and the chosen one's sentence under them
  const note = gEl('mxHowNote');
  const chosen = document.querySelector('.mx-opt.active span');
  if (note) note.textContent = chosen ? chosen.textContent : '';
  gEl('btnMxCreate').textContent = how === 'now' ? 'Charge now' : (how === 'every' ? 'Create subscription' : 'Create sale');
}

function mxOpenTerminal(amount) {
  if (typeof switchView === 'function') switchView('send');
  if (typeof setSendMode === 'function') setSendMode('request');
  if (window.mobileLayout) window.mobileLayout.open('send', 'POS');
  const box = gEl('reqAmount');
  if (!box) return;
  if (amount > 0) { box.value = String(amount); const go = gEl('btnRequest'); if (go) go.click(); }
  else box.focus({ preventScroll: true });
}

async function mxCreate() {
  const title = gEl('mxTitle').value.trim();
  const price = parseFloat(gEl('mxPrice').value);
  if (!title) { gSay('mxStatus', 'Enter a description.', true); return; }
  if (!(price > 0)) { gSay('mxStatus', 'Enter the price.', true); return; }
  gSay('mxStatus', '');
  if (goods.how === 'now') { mxOpenTerminal(price); return; }
  const picked = goods.how === 'file' ? gEl('mxFile').files[0] : null;
  if (goods.how === 'file' && !picked) { gSay('mxStatus', 'Choose the file to sell.', true); return; }
  if (picked && picked.size > 64 * 1024 * 1024) { gSay('mxStatus', 'This file is larger than 64 MB.', true); return; }
  const go = gEl('btnMxCreate');
  go.disabled = true;
  try {
    const extra = (id) => (goods.how === 'held' && gEl(id) ? (parseFloat(gEl(id).value) || 0) : 0);
    const as_name = (typeof state !== 'undefined' && state.myUsername) || null;
    let made;
    if (picked) {
      // the file is sealed, proven and stored before the link exists; the wallet asks first, with the storage price
      gSay('mxStatus', 'Sealing the file and storing it on the network…');
      made = await walletCore('sale_offer_download', { title, amount_usdm: price, hours: 72, name: picked.name, base64: await gFileBase64(picked), as_name });
    } else {
      made = await walletCore('sale_offer', {
        title, amount_usdm: price,
        hours: goods.how === 'every' ? 0 : (Number(gEl('mxDays').value) || 72),
        period_hours: goods.how === 'every' ? (Number(gEl('mxEvery').value) || 720) : 0,
        deposit_usdm: extra('mxDeposit'), bond_usdm: extra('mxBond'),
        as_name,
      });
    }
    goods.link = made.link;
    gEl('mxLink').value = made.link;
    gEl('mxLinkTitle').textContent = (made.period ? 'Subscription: ' : (made.download ? 'Download link: ' : 'Payment link: ')) + made.title + ', ' + gUsd(made.amount_atomic)
      + (made.period ? ' per period. Share it with your subscribers.' : (made.download ? '. Share it with your buyers; each one receives the file automatically.' : '. Share it with your buyer.'));
    gEl('mxLinkBox').style.display = '';
    // the form steps aside: what is left on the screen is the one thing to do next
    document.querySelector('.mx-newsale').classList.add('created');
    gSay('mxStatus', made.short ? '' : 'Tip: register a @username in Settings for shorter links.');
    renderSales();
    goodsWatch();
  } catch (e) { gSay('mxStatus', gWhy(e), true); }
  go.disabled = false;
}

async function mxShare() {
  if (!goods.link) return;
  try {
    if (navigator.share) { await navigator.share({ text: goods.link }); return; }
  } catch (_) { return; /* the share sheet was closed */ }
  gSay('mxStatus', (await gCopy(goods.link)) ? 'Link copied.' : 'Select the link below and copy it.');
}

async function renderSales() {
  const box = gEl('goodsSales');
  if (!box) return;
  let held = [];
  let offers = [];
  try { held = await gList('seller'); } catch (_) { held = []; }
  try { offers = (await walletCore('sale_offers')).offers || []; } catch (_) { offers = []; }
  // a relay's pickups are drawn in their own list; a deposit is said on its sale's row
  let pickups = { pickups: [] };
  let deposits = {};
  try { pickups = await walletCore('sale_pickups'); } catch (_) { pickups = { pickups: [] }; }
  try { deposits = await walletCore('sale_deposits'); } catch (_) { deposits = {}; }
  // the carriers whose delivery emails this build accepts as proof of delivery (none until a release lists them)
  let carriers = [];
  try { carriers = (await walletCore('sale_carriers')).carriers || []; } catch (_) { carriers = []; }
  const held_for_relay = new Set((pickups.pickups || []).map((x) => x.id));
  held = held.filter((p) => !held_for_relay.has(p.id));
  box.textContent = '';
  // an offer nobody has paid for yet: the same title and price are not already among the held sales
  // a download stays listed however many buyers paid: one link sells the file to every buyer
  const waiting = offers.filter((o) => o.download || !held.some((p) => p.title === o.title && Number(p.amount) === Number(o.amount_atomic)));
  if (!held.length && !waiting.length) {
    const e = gNode('div', 'goods-empty');
    e.append(gNode('b', null, 'No sales yet'), gNode('span', null, 'Create a sale and share its payment link. Orders appear here when a buyer pays.'));
    box.appendChild(e);
    return;
  }
  for (const p of held) {
    if (p.kind === 'sub') {
      box.appendChild(gRow(Object.assign({}, p, { status: p.locked ? 'Subscription payment' : 'Subscription pending', pill: p.locked ? 'good' : '',
        when: p.deadline_passed ? 'collecting now' : 'due ' + gWhen(p.deadline_ms) + ', collected automatically' }), [], null));
      continue;
    }
    if (p.kind === 'key') {
      box.appendChild(gRow(Object.assign({}, p, { status: p.locked ? 'Paid' : 'Payment pending', pill: p.locked ? 'good' : '',
        when: p.locked ? 'your wallet releases the file and collects the payment automatically' : 'the buyer\'s payment is on its way' }), [], null));
      continue;
    }
    if (p.kind === 'bond') {
      box.appendChild(gRow(Object.assign({}, p, { title: (p.title || 'Sale') + ': delivery bond', status: p.locked ? 'Bond locked' : 'Bond pending', pill: p.locked ? 'good' : '',
        when: 'returns to you when the buyer confirms receipt' }), [], null));
      continue;
    }
    const dep = deposits[p.id];
    const depNote = dep ? ' · deposit ' + gUsd(dep.amount_atomic) + (Number(dep.received_atomic) >= Number(dep.amount_atomic) ? ' received' : ' pending') : '';
    const view = Object.assign({}, p, p.locked
      ? { status: 'Payment in escrow', pill: 'good', when: 'deliver the order; payment is released when the buyer confirms receipt' + depNote }
      : { status: 'Payment pending', pill: '', when: 'deliver only after this shows Payment in escrow' + depNote });
    const field = p.locked ? { summary: 'Enter a release code', placeholder: 'Release code', label: 'Claim payment', run: async (code) => {
      if (!code) return 'Enter the buyer\'s release code.';
      const codes = code.split(/\s+/);
      for (const one of codes) if (!(await walletCore('purchase_check_code', { code: one }))) return 'Invalid release code for this sale. Do not deliver.';
      for (const one of codes) await walletCore('purchase_release', { code: one });
      renderSales();
      return 'Payment received.';
    } } : null;
    // the doorstep: name the parcel before it ships, then hand over the carrier's own "delivered" email as proof
    const fields = field ? [field] : [];
    if (p.locked && carriers.length) {
      fields.push({ summary: 'Add the tracking number', placeholder: 'Tracking number', label: 'Send to buyer', run: async (code) => {
        if (!code) return 'Enter the carrier\'s tracking number.';
        const out = await walletCore('sale_shipped', { id: p.id, tracking: code });
        return 'Tracking number ' + out.tracking + ' sent. The buyer accepts it on their Wallet page; ship once this page says they did.';
      } });
      fields.push({ summary: 'Prove delivery with the carrier\'s email (' + carriers.join(', ') + ')', file: '.eml,message/rfc822', label: 'Send proof', run: async (eml) => {
        if (!eml) return 'Choose the delivery email you saved from the carrier (.eml).';
        await walletCore('sale_delivered', { id: p.id, base64: await gFileBase64(eml) });
        goodsWatch();
        return 'Proof sent. The buyer\'s wallet checks it and releases your payment.';
      } });
    }
    box.appendChild(gRow(view, [['Cancel sale', async () => {
      const out = await walletCore('sale_call_off', { id: p.id });
      if (out.sent) return 'Sale cancelled. The buyer is refunded automatically.';
      await gCopy(out.code);
      return 'Sale cancelled. Refund code for the buyer: ' + out.code;
    }]], fields));
  }
  for (const o of waiting) {
    box.appendChild(gRow({ title: o.title, amount: o.amount_atomic, status: o.download ? 'Listed' : 'Awaiting buyer', pill: o.download ? 'good' : '',
      when: o.download ? 'share the link; every buyer receives the file automatically' : 'share the payment link' },
      [['Copy link', async () => ((await gCopy(o.link)) ? 'Link copied.' : o.link)]], null));
  }
}

// ── the wallets talk: read the private letters and act on them, while there is something to wait for ───────
async function goodsSyncOnce() {
  let said = [];
  let waiting = [];
  try {
    const r = await walletCore('sale_sync');
    said = (r && r.events) || [];
    waiting = (r && r.waiting) || [];
  } catch (_) { return; }
  if (said.length) {
    const line = said[said.length - 1];
    gSay('goodsSellerNews', line);
    gSay('goodsBuyerNews', line);
  } else if (waiting.length) {
    // an order that is not moving says why, in the words of the step that is waiting
    const why = 'Waiting: ' + waiting[0];
    gSay('goodsSellerNews', why);
    gSay('goodsBuyerNews', why);
  }
  // ⛔ THE BACKGROUND REDRAW NEVER TAKES A FIELD OUT FROM UNDER SOMEONE (lane site's finding, 2026-11-10: these three
  //    lists are rebuilt from nothing, so a redraw every 6 s closed the field a merchant was typing a tracking number
  //    into and lost what was typed). While a field in one of the lists has the cursor or holds typed text, the lists
  //    stand as they are; the news line above still updates, and the lists are redrawn on the first sync after.
  if (goodsFieldInUse('goodsPurchases', 'goodsSales', 'mxPickups')) return;
  renderPurchases();
  if (typeof state !== 'undefined' && state.view === 'merchant') { renderSales(); renderTools(); }
}
// Is someone using a field inside one of these lists: the cursor is in it, or it holds text they typed?
function goodsFieldInUse(...ids) {
  const fields = 'input:not([type=checkbox]):not([type=radio]):not([type=button]):not([type=hidden]), textarea, select';
  for (const id of ids) {
    const box = gEl(id);
    if (!box) continue;
    const a = document.activeElement;
    if (a && box.contains(a) && a.matches(fields)) return true;
    for (const f of box.querySelectorAll('input:not([type=checkbox]):not([type=radio]):not([type=button]):not([type=hidden]), textarea')) {
      if (f.value !== f.defaultValue && f.value !== '') return true;
    }
  }
  return false;
}

// Keep in step for a while after anything was started, and whenever the Wallet or Merchant page is open.
function goodsWatch() {
  goods.until = Date.now() + 10 * 60 * 1000;
  goodsSyncOnce();
}

// ── the pickup relay: one switch on the Merchant page, and the parcels this wallet holds ───────────────────
async function renderTools() {
  if (!gEl('mxRelayState')) return;
  let r = { on: false, pickups: [] };
  try { r = await walletCore('sale_pickups'); } catch (_) { r = { on: false, pickups: [] }; }
  gEl('mxRelayState').textContent = r.on ? 'on' : 'off';
  gEl('mxRelayToggle').textContent = r.on ? 'Turn off' : 'Turn on';
  gEl('mxRelayRow').toggleAttribute('data-on', !!r.on);
  const box = gEl('mxPickups');
  box.textContent = '';
  for (const p of r.pickups || []) {
    const view = { title: p.title || 'Parcel', amount: p.amount, locked: p.holding, deadline_passed: false,
      status: p.holding ? 'Holding' : 'Awaiting parcel', pill: p.holding ? 'good' : '',
      when: p.holding ? 'your bond returns when the buyer picks up' : 'pickup by ' + gWhen(p.deadline_ms) };
    const buttons = p.holding || !p.ready ? [] : [['Parcel received', async () => {
      await walletCore('sale_parcel_received', { id: p.id });
      renderTools();
      return 'You are holding this parcel. Your bond is locked until pickup.';
    }, true]];
    box.appendChild(gRow(view, buttons, null));
  }
}

async function mxRelayToggle() {
  const on = gEl('mxRelayState').textContent !== 'on';
  try { await walletCore('sale_relay_set', { on }); gSay('mxToolsStatus', ''); } catch (e) { gSay('mxToolsStatus', gWhy(e), true); }
  renderTools();
}

function loadMerchant() { renderSales(); renderTools(); goodsWatch(); }

// ── proof of income: one switch in Settings; live figures, and a proof whenever the owner asks ───────────────
// OFF unless its owner turned it on, and off again every time the wallet opens: the wallet's core holds the switch in
// memory and refuses the income figures and the proof while it is off, so nothing about income is worked out by default.
const income = { on: false };

// Site hosting (MonerousD Veil): what this wallet's own node holds, read from that node. A local read; nothing is sent.
async function veilHostRefresh() {
  const el = gEl('settingsVeilHost');
  if (!el) return;
  try {
    const h = await walletCore('node_rpc', { path: '/veil/host', body: '' });
    const mb = (n) => (Number(n) / (1024 * 1024)).toFixed(Number(n) < 10 * 1024 * 1024 ? 1 : 0) + ' MB';
    el.textContent = Number(h.budget) > 0
      ? h.sites + (Number(h.sites) === 1 ? ' site, ' : ' sites, ') + mb(h.used) + ' of ' + mb(h.budget)
      : 'not hosting yet';
  } catch (_) { el.textContent = '—'; }
}

async function incomeRefresh() {
  veilHostRefresh();
  const box = gEl('incomeBox');
  if (!box) return;
  try { income.on = !!(await walletCore('proof_tags_state')).on; } catch (_) { income.on = false; }
  const on = income.on;
  gEl('settingsIncomeState').textContent = on ? 'on' : 'off';
  gEl('settingsIncomeToggle').textContent = on ? 'Turn off' : 'Turn on';
  box.hidden = !on;
  if (!on) return;
  try {
    const live = await walletCore('proof_tags_income');
    gEl('incomeTotal').textContent = gUsd(live.total_atomic);
    gEl('incomeCount').textContent = live.payments + (live.payments === 1 ? ' payment' : ' payments') + ' received and held';
    const latest = gEl('incomeLatest');
    latest.textContent = '';
    for (const p of live.latest || []) latest.appendChild(gNode('span', null, '+' + gUsd(p.amount)));
    gEl('btnIncomeProof').disabled = !(live.payments > 0);
  } catch (e) { gSay('incomeStatus', gWhy(e), true); }
}

async function incomeToggle() {
  gSay('incomeStatus', '');
  gEl('incomeForm').hidden = true;
  try { await walletCore('proof_tags_set', { on: !income.on }); }
  catch (e) { gSay('settingsIncomeNote', 'Proof of income stays off: ' + gWhy(e), true); return; }
  incomeRefresh();
}

async function incomeMake() {
  const context = gEl('incomeContext').value.trim();
  const key = gEl('incomeVerifierKey').value.trim();
  if (!context) { gSay('incomeStatus', 'Enter a reference, so the proof cannot be reused elsewhere.', true); return; }
  if (key && !/^[0-9a-fA-F]{64}$/.exec(key)) { gSay('incomeStatus', 'Invalid verifier key. Leave it empty for a proof anyone can verify.', true); return; }
  gSay('incomeStatus', 'Generating proof…');
  try {
    const bundle = await walletCore('proof_tags_make', { verifier_key: key || 'public', context });
    const text = JSON.stringify(bundle);
    const copied = await gCopy(text);
    const count = (bundle.parts || []).reduce((n, p) => n + ((p.notes || []).length), 0);
    gSay('incomeStatus', gUsd(bundle.total_atomic) + ' in ' + count + (count === 1 ? ' payment' : ' payments') + ' (individual amounts stay private), '
      + Math.ceil(text.length / 1024) + ' KB. ' + (copied ? 'Copied: paste it to whoever asked.' : 'Copying was blocked: try again.')
      + (key ? ' Only that verifier can rely on it.' : ' Anyone you send it to can check it.'));
  } catch (e) { gSay('incomeStatus', gWhy(e), true); }
}

async function incomeKey() {
  const label = gEl('incomeLabel').value.trim();
  if (!label) { gSay('incomeCheckStatus', 'Enter a name for who you are checking.', true); return; }
  try {
    const made = await walletCore('proof_tag_verifier_key', { label });
    await gCopy(made.verifier_key);
    gSay('incomeCheckStatus', 'Your key is copied: send it to them. Keep the name, you need it to check their proof.');
  } catch (e) { gSay('incomeCheckStatus', gWhy(e), true); }
}

async function incomeCheck() {
  let bundle = null;
  try { bundle = JSON.parse(gEl('incomeToCheck').value.trim()); } catch (_) { bundle = null; }
  if (!bundle || typeof bundle !== 'object') { gSay('incomeCheckStatus', 'Paste the proof they sent.', true); return; }
  gSay('incomeCheckStatus', 'Checking…');
  try {
    const r = await walletCore('proof_tags_check', { bundle, label: gEl('incomeLabel').value.trim() || 'anyone' });
    gSay('incomeCheckStatus', 'Valid: ' + gUsd(r.total_atomic) + ' in ' + r.notes + (r.notes === 1 ? ' payment' : ' payments')
      + ' to their address, for "' + r.context + '". Your own node confirms ' + r.confirmed + ' of ' + r.notes + ' of them on the chain.');
  } catch (e) { gSay('incomeCheckStatus', 'Not valid: ' + gWhy(e), true); }
}

// ── Settings: a switch that LOOKS on when it is on ─────────────────────────────────────────────────────────
// The page's own code writes each setting's state as words ("on", "off — not private") and labels the button with the
// action ("Turn off"). Read that state and draw the button as a switch, so what is on is seen at a glance.
function settingsSwitches() {
  for (const [stateId, buttonId] of [['settingsOpsecState', 'settingsOpsecToggle'], ['settingsSupportState', 'settingsSupportToggle'], ['settingsIncomeState', 'settingsIncomeToggle']]) {
    const said = gEl(stateId);
    const button = gEl(buttonId);
    if (!said || !button) continue;
    const row = button.closest('.settings-row');
    const sync = () => {
      const on = /^on\b/i.exec(said.textContent.trim()) !== null;
      button.classList.add('switch');
      button.setAttribute('role', 'switch');
      button.setAttribute('aria-checked', on ? 'true' : 'false');
      if (row) row.dataset.on = on ? '1' : '0';
    };
    new MutationObserver(sync).observe(said, { childList: true, characterData: true, subtree: true });
    sync();
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const on = (id, fn) => { const e = gEl(id); if (e) e.addEventListener('click', fn); };
  // paying a link from the Pay box: a link in "Pay to" is read first instead of being sent as an address
  const to = gEl('sendTo');
  if (to) to.addEventListener('input', goodsToChanged);
  const send = gEl('btnSend');
  if (send) send.addEventListener('click', (e) => {
    if (!isLink(gEl('sendTo').value)) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    goodsReviewLink();
  }, true);
  on('btnGoodsPay', goodsPayLink);
  on('btnMxCreate', mxCreate);
  on('btnMxShare', mxShare);
  on('btnMxAnother', () => {
    document.querySelector('.mx-newsale').classList.remove('created');
    gEl('mxLinkBox').style.display = 'none';
    gEl('mxTitle').value = '';
    gEl('mxPrice').value = '';
    if (gEl('mxFile')) gEl('mxFile').value = '';
    gSay('mxStatus', '');
    gEl('mxTitle').focus();
  });
  on('btnMxCopy', async () => gSay('mxStatus', (await gCopy(goods.link)) ? 'Link copied.' : 'Select the link below and copy it.'));
  for (const b of document.querySelectorAll('.mx-opt')) b.addEventListener('click', () => mxHow(b.dataset.how));
  on('mxRelayToggle', mxRelayToggle);
  on('settingsIncomeToggle', incomeToggle);
  on('btnIncomeProof', () => { const f = gEl('incomeForm'); f.hidden = !f.hidden; if (!f.hidden) gEl('incomeContext').focus(); });
  on('btnIncomeMake', incomeMake);
  on('btnIncomeKey', incomeKey);
  on('btnIncomeCheck', incomeCheck);
  incomeRefresh();
  settingsSwitches();
  renderPurchases();
  // live: Settings' income figures while that page is open; the wallets' letters while something is being waited for
  const nav = gEl('nav');
  if (nav) nav.addEventListener('click', (e) => {
    const item = e.target.closest('.nav-item');
    if (item && item.dataset.view === 'settings') setTimeout(incomeRefresh, 0);
    if (item && item.dataset.view === 'wallet') setTimeout(renderPurchases, 0);
  });
  setInterval(() => {
    if (document.visibilityState !== 'visible' || typeof state === 'undefined') return;
    if (income.on && state.view === 'settings') incomeRefresh();
    if (state.view === 'merchant' || state.view === 'wallet' || (goods.until && Date.now() < goods.until)) goodsSyncOnce();
  }, 6000);
  try {
    const T = window.__TAURI__;
    if (T && T.event) T.event.listen('checkout:link', (evt) => goodsOpenLink(String(evt.payload || '')));
    if (T) walletCore('checkout_pending_link').then((link) => { if (link) goodsOpenLink(link); }).catch(() => {});
  } catch (_) {}
});
