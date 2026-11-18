// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// pages/swap.js — NATIVE ASSET SWAPS (2026-11-10): the front page. Coin for coin through the one bridge; the wallet
// that frames this page prices, confirms and acts (lib/native.js says how). What each control does:
//   * the amount, the two coins, the flip: only this page's estimate; nothing is sent
//   * Auto-OPSEC switch: asks the WALLET to change its one privacy setting (off passes the wallet's own warning)
//   * Swap: asks the wallet to start the swap; the wallet shows every cost in dollars in its own sheet, and on yes
//     makes the deposit address (or pays out, for MoneroUSD → coin); this page then shows what the wallet answered
//
// TWO-PARTY-REVIEWED: a page, not a test. Its second party is the wallet that frames it (lib/wallet-bridge.js,
// messages across two origins); that crossing is exercised with the real wallet and node, never inside this file.
import { S, PRICE, asset, routeOf, ask, learn, onLearned, provider, priceLine, esc, usd, coinAmt, coinDot, CHAIN_WORDS, reduced, connectNote } from '../lib/native.js';

let root = null;
const $ = (s) => (root ? root.querySelector(s) : null);

function estimate() {
  const r = routeOf(S.from, S.to);
  const amount = Number(S.amount);
  const [a, b] = [asset(S.from), asset(S.to)];
  if (!r || !(amount > 0)) return { r, ok: false };
  if (r.fee_pct == null || !a.usd || !b.usd) return { r, ok: false, unpriced: true };
  const fee = (amount * r.fee_pct) / 100; // the amount is in dollars: the wallet prices both coins itself before it asks
  return { r, ok: true, usdIn: amount, fee, usdOut: amount - fee, pay: amount / a.usd, get: (amount - fee) / b.usd };
}

const paySub = (e, a) => (e.ok ? '≈ ' + coinAmt(e.pay) + ' ' + a.sym + ' · ' + CHAIN_WORDS[a.chain] : a.name + ' · ' + CHAIN_WORDS[a.chain]);
const getSub = (e, b) => (e.ok ? usd(e.usdOut) + ' after ' + usd(e.fee) + ' in fees · ' + CHAIN_WORDS[b.chain] : e.unpriced ? (PRICE.why ? 'Waiting for the chain\'s price' : 'Priced by your wallet before you confirm') : b.name + ' · ' + CHAIN_WORDS[b.chain]);

// The button's words and whether it can be pressed: one rule for the first draw and for every keystroke.
function goState() {
  const e = estimate();
  const blocked = S.to === 'BTC' && S.dest === 'addr' && S.opsec;
  const needAddr = (S.to === 'XMR' || (S.to === 'BTC' && S.dest === 'addr')) && !S.addr.trim();
  const noRoute = !e.r;
  const viaWallet = !!(e.r && e.r.kind === 'wallet');
  const label = !S.wallet ? 'Connect wallet to swap' : noRoute ? 'This pair is not traded' : viaWallet ? 'Trade SAT in the wallet' : S.busy ? 'Waiting for your wallet…' : 'Swap ' + S.from + ' to ' + S.to;
  const disabled = S.busy || (S.wallet && (noRoute || (!viaWallet && (!(Number(S.amount) > 0) || needAddr || blocked))));
  return { label, disabled };
}

// What each coin costs and where that number comes from: the chain's own price mark, never a company's feed.
function ratesHtml(a, b) {
  const lines = [a, b].map(priceLine).filter(Boolean);
  if (!lines.length && !PRICE.why) return '';
  return '<div class="rates">' + lines.map((l) => '<span class="num">' + esc(l) + '</span>').join('') +
    (PRICE.why ? '<span class="why">' + esc(PRICE.why) + '</span>' : '') + '</div>';
}

function cardHtml() {
  const [a, b] = [asset(S.from), asset(S.to)];
  const e = estimate();
  const toPublic = b.chain === 'public';
  let dest;
  if (S.to === 'BTC') {
    dest =
      '<div class="stack"><span class="muted">Receive in</span>' +
      '<div class="seg"><button type="button" data-dest="vault" class="' + (S.dest === 'vault' ? 'on' : '') + '">My Bitcoin vault</button>' +
      '<button type="button" data-dest="addr" class="' + (S.dest === 'addr' ? 'on' : '') + '">An address</button></div>' +
      (S.dest === 'addr'
        ? '<input class="field mono" id="ionAddr" placeholder="A Bitcoin address" value="' + esc(S.addr) + '" autocomplete="off" spellcheck="false" autocapitalize="off">' +
          (S.opsec ? '<div class="note warn">With Auto-OPSEC on, Bitcoin is paid to your own vault, a fresh address for every piece: every piece to one address would add up to the swap and point back at you.</div>' : '')
        : '<div class="muted">A fresh address of your own for every piece. Only your 24 words open them.</div>') +
      '</div>';
  } else if (S.to === 'XMR') {
    dest = '<div class="stack"><span class="muted">Receive at</span><input class="field mono" id="ionAddr" placeholder="Your Monero address" value="' + esc(S.addr) + '" autocomplete="off" spellcheck="false" autocapitalize="off"></div>';
  } else {
    dest = '<div class="muted">Arrives in this wallet, private.</div>';
  }
  const go = goState();
  return (
    '<div class="legs">' +
    '<div class="leg"><label for="ionAmount">You pay, in dollars</label>' +
    '<input id="ionAmount" inputmode="decimal" placeholder="0.00" autocomplete="off" value="' + esc(S.amount) + '">' +
    '<button type="button" class="asset" data-pick="from">' + coinDot(a.sym) + esc(a.sym) + '</button>' +
    '<div class="sub" id="ionPaySub">' + esc(paySub(e, a)) + '</div></div>' +
    '<button type="button" class="flip" id="ionFlip" aria-label="Switch the two coins"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 4v14M3.5 14.5 7 18l3.5-3.5M17 20V6M13.5 9.5 17 6l3.5 3.5"/></svg></button>' +
    '<div class="leg"><label>You receive</label>' +
    '<div class="out num" id="ionGetOut">' + (e.ok ? coinAmt(e.get) : '0') + '</div>' +
    '<button type="button" class="asset" data-pick="to">' + coinDot(b.sym) + esc(b.sym) + '</button>' +
    '<div class="sub" id="ionGetSub">' + esc(getSub(e, b)) + '</div></div>' +
    '</div>' +
    ratesHtml(a, b) +
    dest +
    '<div class="opsec' + (S.opsec ? '' : ' off') + '"><b>Auto-OPSEC ' + (S.opsec ? 'on' : 'off') + '</b>' +
    '<button type="button" class="switch" id="ionOpsec" role="switch" aria-checked="' + S.opsec + '" aria-label="Auto-OPSEC"' + (S.wallet ? '' : ' disabled') + '></button>' +
    '<span>' + (S.opsec
      ? (toPublic ? 'Paid in standard pieces, each to a fresh address of yours, each in its own batch among other people\'s.' : 'Paid in standard pieces, each in its own batch among other people\'s.')
      : 'Paid at once. Not private: anyone watching the two chains can match this swap.') + '</span></div>' +
    (S.err ? '<div class="note bad">' + esc(S.err) + '</div>' : '') +
    '<button type="button" class="cta" id="ionGo"' + (go.disabled ? ' disabled' : '') + '>' + esc(go.label) + '</button>' +
    '<div class="muted">' + (S.wallet ? 'Your wallet shows every cost in dollars and asks before anything moves.' : 'Swaps are signed and sent by your own wallet, through its own node. Connect it with the button at the top, or press Swap.') + '</div>'
  );
}

// The route drawn: what leaves one chain, what arrives on the other, and nothing between them to follow.
function routeHtml() {
  const [a, b] = [asset(S.from), asset(S.to)];
  const e = estimate();
  const pieces = S.opsec && b.chain !== 'private' ? 5 : 1;
  const mid = 118;
  const lanes = [];
  for (let i = 0; i < pieces; i++) {
    const y = pieces === 1 ? mid : mid - 52 + (i * 104) / (pieces - 1);
    lanes.push(
      '<path id="ionLn' + i + '" class="lane live' + (S.opsec ? ' veil' : '') + '" d="M330 ' + mid + ' C 400 ' + mid + ', 420 ' + y + ', 500 ' + y + '" style="animation-delay:' + i * -0.3 + 's"/>' +
      (reduced ? '' : '<circle r="4.2" fill="' + (S.opsec ? '#b9aeff' : '#ff9b9b') + '"><animateMotion dur="' + (2.2 + i * 0.5) + 's" begin="' + i * 0.55 + 's" repeatCount="indefinite"><mpath href="#ionLn' + i + '"/></animateMotion></circle>') +
      '<circle cx="508" cy="' + y + '" r="5" fill="none" stroke="' + (S.opsec ? '#8b7bff' : '#ff5d6c') + '" stroke-width="1.5"/>');
  }
  // (the gradients are in the drawing's own coordinates: a level line has no box of its own to stretch one over)
  const svg =
    '<svg viewBox="0 0 560 196" role="img" aria-label="' + esc(a.name + ' goes in, ' + b.name + ' comes out' + (pieces > 1 ? ' in separate pieces' : ' in one payment')) + '">' +
    '<defs><linearGradient id="ionG1" gradientUnits="userSpaceOnUse" x1="30" y1="0" x2="230" y2="0"><stop offset="0" stop-color="#ffa24d"/><stop offset="1" stop-color="#ff6a00"/></linearGradient>' +
    '<linearGradient id="ionG2" gradientUnits="userSpaceOnUse" x1="330" y1="0" x2="510" y2="0"><stop offset="0" stop-color="#ff8a3d"/><stop offset="1" stop-color="#8b7bff"/></linearGradient></defs>' +
    '<text x="24" y="22" class="tag">' + esc(CHAIN_WORDS[a.chain]) + '</text><text x="24" y="42" class="big">' + esc(a.name) + '</text>' +
    '<circle cx="52" cy="' + mid + '" r="22" fill="none" stroke="url(#ionG1)" stroke-width="2"/><text x="52" y="' + (mid + 5) + '" text-anchor="middle" class="big">' + esc(a.sym === 'USDm' ? '$' : a.sym.slice(0, 1)) + '</text>' +
    '<path id="ionLin" class="lane live" d="M78 ' + mid + ' L 226 ' + mid + '"/>' +
    (reduced ? '' : '<circle r="4.6" fill="#ffb066"><animateMotion dur="2s" repeatCount="indefinite"><mpath href="#ionLin"/></animateMotion></circle>') +
    '<rect x="230" y="' + (mid - 38) + '" width="100" height="76" rx="18" class="core' + (S.opsec ? '' : ' off') + '"/>' +
    '<text x="280" y="' + (mid - 4) + '" text-anchor="middle" class="big">' + (S.opsec ? 'Private' : 'Open') + '</text>' +
    '<text x="280" y="' + (mid + 14) + '" text-anchor="middle" class="tag">' + (S.opsec ? 'no link kept' : 'linkable') + '</text>' +
    lanes.join('') +
    '<text x="536" y="22" text-anchor="end" class="tag">' + esc(CHAIN_WORDS[b.chain]) + '</text><text x="536" y="42" text-anchor="end" class="big">' + esc(b.name) + '</text>' +
    '</svg>';
  const fee = e.r && e.r.fee_pct != null ? e.r.fee_pct.toFixed(2) + '%' : 'in wallet';
  const paced = S.opsec && b.chain !== 'private';
  return (
    svg +
    '<div class="facts">' +
    '<div class="fact"><b class="num">' + esc(fee) + '</b><span>fees, shown in dollars first</span></div>' +
    '<div class="fact"><b>' + (paced ? 'In pieces' : 'At once') + '</b><span>' + (paced ? 'each in its own batch, inside a day' : b.chain === 'private' ? 'straight into your wallet' : 'the next batch') + '</span></div>' +
    '<div class="fact"><b>' + (S.opsec ? '≈ 2 in 100' : '9 in 10') + '</b><span>pieces an analyst can link' + (S.opsec ? ', at most' : '') + '</span></div>' +
    '</div>'
  );
}

function paint() {
  if (!root || !$('#ionCard')) return;
  const focus = document.activeElement && document.activeElement.id;
  const caret = focus && document.activeElement.selectionStart;
  $('#ionCard').innerHTML = cardHtml();
  $('#ionRoute').innerHTML = routeHtml();
  wire();
  if (focus && root.querySelector('#' + focus)) {
    const el = root.querySelector('#' + focus);
    el.focus();
    if (caret != null && el.setSelectionRange) el.setSelectionRange(caret, caret);
  }
  paintAfter();
}

function syncGo() {
  const go = goState();
  $('#ionGo').disabled = go.disabled;
  $('#ionGo').textContent = go.label;
}

function wire() {
  const amount = $('#ionAmount');
  amount.addEventListener('input', () => {
    S.amount = amount.value.replace(/[^0-9.]/g, '').replace(/(\..*)\./g, '$1');
    if (amount.value !== S.amount) amount.value = S.amount;
    // only the figures move while typing: the field keeps its caret
    const e = estimate();
    $('#ionPaySub').textContent = paySub(e, asset(S.from));
    $('#ionGetOut').textContent = e.ok ? coinAmt(e.get) : '0';
    $('#ionGetSub').textContent = getSub(e, asset(S.to));
    syncGo();
  });
  const addr = $('#ionAddr');
  if (addr) addr.addEventListener('input', () => { S.addr = addr.value; syncGo(); });
  root.querySelectorAll('[data-dest]').forEach((b) => b.addEventListener('click', () => { S.dest = b.dataset.dest; if (S.dest === 'vault') S.addr = ''; paint(); }));
  root.querySelectorAll('[data-pick]').forEach((b) => b.addEventListener('click', () => pick(b.dataset.pick)));
  $('#ionFlip').addEventListener('click', () => {
    $('#ionFlip').classList.add('turn');
    [S.from, S.to] = [S.to, S.from];
    S.addr = ''; S.dest = 'vault';
    setTimeout(paint, reduced ? 0 : 220);
  });
  $('#ionOpsec').addEventListener('click', toggleOpsec);
  $('#ionGo').addEventListener('click', go);
}

function pick(side) {
  const other = side === 'from' ? S.to : S.from;
  const sheet = document.createElement('div');
  sheet.className = 'ion ion-sheet';
  sheet.innerHTML =
    '<div class="sheet-card" role="dialog" aria-modal="true" aria-label="Choose a coin"><h2>' + (side === 'from' ? 'You pay with' : 'You receive') + '</h2>' +
    S.assets.map((a) => {
      const r = side === 'from' ? routeOf(a.sym, other) : routeOf(other, a.sym);
      const same = a.sym === other;
      return '<button type="button" class="pick" data-sym="' + esc(a.sym) + '">' + coinDot(a.sym) + '<b>' + esc(a.name) + '</b><span class="num">' + (a.usd ? usd(a.usd) : '') + '</span>' +
        '<small>' + esc(a.sym + ' · ' + CHAIN_WORDS[a.chain]) + (same ? ' · switches the two' : r ? '' : ' · changes the other coin') + '</small></button>';
    }).join('') +
    '<button type="button" class="ghost" data-close>Close</button></div>';
  document.body.appendChild(sheet);
  const close = () => sheet.remove();
  sheet.addEventListener('click', (ev) => { if (ev.target === sheet || ev.target.closest('[data-close]')) close(); });
  sheet.querySelectorAll('.pick').forEach((b) => b.addEventListener('click', () => {
    const sym = b.dataset.sym;
    if (sym === other) [S.from, S.to] = [S.to, S.from];
    else if (side === 'from') S.from = sym;
    else S.to = sym;
    // a pair the bridge does not trade: keep the coin just chosen and move the other to one it trades with
    if (!routeOf(S.from, S.to)) {
      const fix = S.assets.map((a) => a.sym).find((x) => (side === 'from' ? routeOf(S.from, x) : routeOf(x, S.to)));
      if (fix) { if (side === 'from') S.to = fix; else S.from = fix; }
    }
    S.addr = ''; S.dest = 'vault';
    close();
    paint();
  }));
}

async function toggleOpsec() {
  if (!S.wallet) return;
  try {
    // OFF is answered by the wallet's own warning sheet; this page only shows what the wallet decided
    const r = await ask('setAutoOpsec', { on: !S.opsec }, 180000);
    S.opsec = !(r && r.on === false);
    S.err = '';
  } catch (e) {
    S.err = String((e && e.message) || e);
  }
  paint();
}

async function go() {
  const after = $('#ionAfter');
  if (!S.wallet) {
    // no wallet is answering yet: the same press connects one (the header's Connect button does the same)
    S.err = '';
    S.last = { kind: 'no_wallet' };
    paintAfter();
    document.getElementById('connect-btn')?.click();
    return;
  }
  S.busy = true; S.err = '';
  paint();
  try {
    const payoutTo = S.to === 'XMR' || (S.to === 'BTC' && S.dest === 'addr') ? S.addr.trim() : '';
    S.last = await ask('nativeSwap', { from: S.from, to: S.to, usd: Number(S.amount) || 0, payoutTo }, 600000);
    const dot = document.getElementById('activityDot');
    if (dot && S.last && S.last.kind !== 'declined') dot.hidden = false;
  } catch (e) {
    S.err = String((e && e.message) || e);
    S.last = null;
  }
  S.busy = false;
  paint();
  if (S.last && $('#ionAfter')) $('#ionAfter').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
}

function paintAfter() {
  const el = $('#ionAfter');
  if (!el) return;
  const r = S.last;
  const follow = '<a class="ghost" href="#/activity" style="justify-self:start;text-decoration:none">Follow it in Activity</a>';
  if (!r || r.kind === 'declined') { el.innerHTML = ''; return; }
  if (r.kind === 'no_wallet') {
    el.innerHTML = '<div class="card stack"><h2>Connect your wallet to swap</h2>' + connectNote('to swap') + '<div class="steps">' +
      '<div><div><b>Your wallet asks you to approve this site</b><span>It runs its own node: that node reads the chain for this page and sends your swap.</span></div></div>' +
      '<div><div><b>Swap</b><span>Your wallet shows every cost in dollars and asks before anything moves.</span></div></div></div></div>';
    return;
  }
  if (r.kind === 'wallet_page') { el.innerHTML = '<div class="note ok">' + esc(r.note || 'Continue on the wallet\'s Buy / Sell page.') + '</div>'; return; }
  if (r.kind === 'cashout') {
    const p = r.plan || {};
    const n = p.parts_total || (p.pieces || []).length || 0;
    el.innerHTML = '<div class="card stack"><h2>Your swap is on its way</h2>' +
      '<div class="note ok">' + esc((n ? n + ' piece(s) of ' : 'Your ') + (p.asset || S.to) + ' will arrive' + (p.about_hours_left != null ? ' within about ' + Math.max(1, Math.ceil(Number(p.about_hours_left))) + ' hour(s)' : '') + '. Nothing else is needed from you.') + '</div>' + follow + '</div>';
    return;
  }
  if (r.kind === 'private_deposit') {
    const p = r.plan || {};
    el.innerHTML = '<div class="card stack"><h2>Send your Bitcoin to your private deposit address</h2>' +
      (p.receive_address ? '<div class="qr" id="ionQr"></div><div class="addr mono">' + esc(p.receive_address) + '</div><button type="button" class="ghost" id="ionCopy">Copy address</button>' : '') +
      '<div class="note">' + esc(p.note || 'Your wallet mixes the deposit with other people\'s before it enters, then finishes the swap on its own.') + '</div>' + follow + '</div>';
    paintQr(p.receive_address);
    return;
  }
  if (r.kind === 'deposit') {
    const q = r.swap || {};
    el.innerHTML = '<div class="card stack"><h2>Send exactly this, to this address</h2>' +
      (q.deposit_address
        ? '<div class="qr" id="ionQr"></div>' +
          (q.deposit_amount != null ? '<div class="row"><span class="muted">Amount</span><b class="num">' + esc(coinAmt(q.deposit_amount, 12)) + ' ' + esc(q.asset || S.from) + '</b></div>' : '') +
          '<div class="addr mono">' + esc(q.deposit_address) + '</div><button type="button" class="ghost" id="ionCopy">Copy address</button>'
        : '<div class="note">Your deposit address is being made by the reserve\'s validators. It appears here in a moment.</div>') +
      '<div class="note warn">Send on the ' + esc(q.asset || S.from) + ' network only, the exact amount, once. The rest of the swap runs on its own once your deposit confirms.</div>' + follow + '</div>';
    paintQr(q.deposit_address);
    if (!q.deposit_address) setTimeout(pollDeposit, 3000);
  }
}

// The address appears once the validators answer: read it from the wallet's own record of this swap.
async function pollDeposit() {
  if (!root || !S.last || S.last.kind !== 'deposit' || (S.last.swap && S.last.swap.deposit_address)) return;
  try {
    const p = await ask('nativeProgress');
    const list = (p && p.swaps && p.swaps.swaps) || [];
    const mine = list.find((s) => s.swap_id === (S.last.swap || {}).swap_id);
    if (mine && mine.deposit_address) { S.last.swap = mine; paintAfter(); return; }
  } catch (_) { /* asked again below */ }
  setTimeout(pollDeposit, 4000);
}

async function paintQr(text) {
  const box = $('#ionQr');
  const copy = $('#ionCopy');
  if (copy) copy.onclick = async () => { try { await navigator.clipboard.writeText(text); copy.textContent = 'Copied'; } catch (_) { copy.textContent = 'Select the address and copy it'; } };
  if (!box || !text || !provider()) return;
  try {
    const r = await provider().qrSvg(text);
    const svg = typeof r === 'string' ? r : r && (r.svg || r.qr);
    // the wallet draws the code; only a bare <svg> with nothing active in it is put on the page
    if (typeof svg === 'string' && /^\s*<svg[\s>]/i.test(svg) && !/<script|\son\w+\s*=|javascript:/i.test(svg)) box.innerHTML = svg;
    else box.remove();
  } catch (_) { box.remove(); }
}

let unlisten = null;
export default async function render(view /* , ctx */) {
  root = document.createElement('section');
  root.className = 'ion page';
  root.innerHTML =
    '<div><div class="eyebrow">Coin for coin · nothing wrapped</div>' +
    '<h1>Swap coins.<br><em>Leave no trail.</em></h1>' +
    '<p class="lead">Bitcoin in, Monero out, or the other way round: the coins themselves, through one bridge. Nobody watching the two chains can match what went in to what came out.</p></div>' +
    '<div class="swap-grid"><div class="card glow stack" id="ionCard"></div><div class="card route" id="ionRoute"></div></div>' +
    // tokens people made are bought and sold in their own pools, not through the bridge: this page says where (two links, nothing sent)
    '<p class="muted">Looking for a token someone made? <a href="#/tokens">Find it on Tokens</a> or <a href="#/pools">open its pool</a>: buy, sell, or swap into another token in one order.</p>' +
    '<div id="ionAfter"></div>';
  view.appendChild(root);
  if (unlisten) unlisten();
  unlisten = onLearned(paint);
  paint();
  learn();
}
