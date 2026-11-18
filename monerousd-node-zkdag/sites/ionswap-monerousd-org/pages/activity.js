// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// pages/activity.js — what is in flight for this user (2026-11-10): deposits, payouts in pieces, SAT orders.
// The framing wallet answers (`nativeProgress`) from its own books and its own node, a bounded answer of the
// latest few entries; nobody else is asked, and nothing here sends or spends.
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. Its second party is the wallet that frames it
// (lib/wallet-bridge.js); that crossing is exercised with the real wallet and node, never inside this file.
import { S, ask, learn, esc, usd, coinAmt, coinDot, connectNote, privateNote, isHidden } from '../lib/native.js';
import { paint } from '../lib/paint.js';
import * as pl from '../lib/pools.js';

const STATUS_WORDS = {
  awaiting_reserve: 'Making your deposit address',
  awaiting_deposit: 'Waiting for your deposit',
  confirming: 'Deposit seen, confirming',
  gathering_quorum: 'Validators are signing',
  published: 'On its way into a block',
  minted: 'Arrived in your wallet',
  redeemed: 'Paid out',
  reclaimed: 'Returned to you',
};
const hoursWords = (h) => 'within about ' + Math.max(1, Math.ceil(Number(h))) + ' hour(s)';
const SHOWN = 12; // the latest few of each kind

function rows(p) {
  const items = [];
  const swaps = (p.swaps && p.swaps.swaps) || [];
  for (const s of swaps.slice(-SHOWN).reverse()) {
    const done = ['minted', 'redeemed', 'reclaimed'].includes(s.status);
    items.push('<div class="item">' + coinDot(s.asset || 'BTC') + '<div class="t">' + esc((s.asset || '') + ' deposit' + (s.usdm_out ? ' · ' + usd(s.usdm_out) : '')) + '</div>' +
      '<span class="chip ' + (done ? 'done' : 'live') + '">' + esc(STATUS_WORDS[s.status] || s.status || 'In flight') + '</span>' +
      '<div class="s mono">' + esc(s.swap_id || '') + '</div></div>');
  }
  for (const c of ((p.cash && p.cash.plans) || []).slice(0, SHOWN)) {
    const total = Number(c.parts_total) || (c.pieces || []).length || 0;
    const sent = Number(c.parts_sent) || 0;
    const done = total > 0 && sent >= total;
    items.push('<div class="item">' + coinDot(c.asset || 'BTC') + '<div class="t">' + esc('Paying out ' + (c.asset || '') + (c.usdm_requested ? ' · ' + usd(c.usdm_requested) : '')) + '</div>' +
      '<span class="chip ' + (done ? 'done' : 'live') + '">' + esc(sent + ' of ' + total + ' pieces') + '</span>' +
      '<div class="s">' + esc(done ? 'Every piece is sent.' : c.fast ? 'In the next batch (Auto-OPSEC was off).' : c.about_hours_left != null ? 'The last piece ' + hoursWords(c.about_hours_left) + ': each piece waits for its own batch.' : 'Each piece waits for its own batch.') + '</div>' +
      '<div class="bar"><i style="--p:' + (total ? Math.round((sent / total) * 100) : 0) + '%"></i></div></div>');
  }
  const sat = p.sat || {};
  for (const o of (sat.payouts || []).slice(0, SHOWN)) {
    const sym = /xmr|monero/i.test(String(o.coin)) ? 'XMR' : 'BTC';
    items.push('<div class="item">' + coinDot(sym) + '<div class="t">' + esc('SAT sale paying out · ' + coinAmt(Number(o.sent) + Number(o.left)) + ' ' + (o.coin || '')) + '</div>' +
      '<span class="chip live">' + esc((o.pieces_left != null ? o.pieces_left : '') + ' piece(s) left') + '</span>' +
      '<div class="s">' + esc((o.to_vault ? 'To your own vault, a fresh address for every piece. ' : '') + (o.auto_opsec ? (o.on_its_way_ms ? 'What is on its way arrives ' + hoursWords(Number(o.on_its_way_ms) / 3600000) + '.' : 'Each piece waits for its own batch.') : 'Paid at once (Auto-OPSEC was off).')) + '</div></div>');
  }
  for (const o of (sat.orders || []).slice(0, 8)) {
    items.push('<div class="item">' + coinDot('SAT') + '<div class="t">' + esc((o.sell ? 'Selling SAT for ' : 'Buying SAT with ') + (o.coin || '')) + '</div><span class="chip live">' + esc(o.status || 'in the next batch') + '</span><div class="s">A sealed order: nobody sees its size or its side before the batch clears.</div></div>');
  }
  for (const m of ((p.mix && p.mix.plans) || []).slice(0, 6)) {
    items.push('<div class="item">' + coinDot('BTC') + '<div class="t">Private Bitcoin deposit</div><span class="chip live">' + esc((m.minted || 0) + ' arrived') + '</span><div class="s">' + esc(m.note || '') + '</div></div>');
  }
  return items;
}

// ── POOL ORDERS: what the wallet sent to a pool since it was opened, and what each was PAID. The wallet reads the
// payouts from its own notes (an order's payout notes are its alone), so a row says "received" only when the note is
// in the wallet. An order is paid a block or two after it is sent; the wallet keeps this list in memory only.
const names = new Map(); // a token's symbol by its id, read once from the wallet's node
async function symbolOf(token) {
  if (!token) return '';
  if (!names.has(token)) {
    let sym = '';
    try { const r = await ask('ionPool', { token }, 25000); sym = (r && ((r.pool && r.pool.symbol) || (r.asset && r.asset.symbol))) || ''; } catch (_) { /* the id's first characters stand in */ }
    names.set(token, sym || 'token ' + String(token).slice(0, 6) + '…');
  }
  return names.get(token);
}
const WAITING = 'A block carries it and the next one pays it, usually within a minute.';
// The chip says what HAPPENED, never only that something arrived: an order handed back is not "paid".
const CHIP = { wait: ['live', 'In flight'], paid: ['done', 'Paid'], back: ['', 'Handed back'], sent: ['live', 'Sent'] };
function poolRow(o, sym, hopSym) {
  const got = (name) => (o.paid || []).filter((p) => p.asset === name).reduce((a, p) => a + pl.big(p.atomic), 0n);
  const [tok, usdm, share, hop] = [got('token'), got('usdm'), got('share'), got('hop_token')];
  // spec §14: shares paid locked until the order's new date, and locked shares handed back as they were
  const [lockedNew, lockedBack] = [got('locked'), got('locked_back')];
  const fromDate = o.lock_from_date ? o.lock_from_date : '', untilDate = o.lock_until_date ? o.lock_until_date : '';
  const u = (v) => coinAmt(pl.whole(v), 4), m = (v) => usd(pl.whole(v));
  // what came back or arrived, naming only what is more than nothing
  const both = (t, d) => [t > 0n ? u(t) + ' ' + sym : '', d > 0n ? m(d) : ''].filter(Boolean).join(' and ') || 'nothing';
  const moved = 'The price moved past the least you accept, so ';
  let title = 'Pool order · ' + sym, sub = WAITING, chip = CHIP.wait;
  const say = (state, words) => { chip = CHIP[state]; sub = words; };
  if (o.kind === 0) {
    title = 'Buy ' + sym + ' · ' + m(o.y);
    if (o.settled && tok > 0n) say('paid', 'You received ' + u(tok) + ' ' + sym + '.');
    else if (o.settled) say('back', moved + 'your ' + m(usdm) + ' is back in your wallet.');
  } else if (o.kind === 1 && o.hop) {
    title = 'Swap ' + u(o.x) + ' ' + sym + ' for ' + hopSym;
    if (!o.settled) sub = 'Two pools, one block after the other: ' + sym + ' is sold first, then ' + hopSym + ' is bought with what it earned.';
    else if (hop > 0n) say('paid', 'You received ' + u(hop) + ' ' + hopSym + '.');
    else if (usdm > 0n) say('paid', 'The ' + hopSym + ' pool could not give the least you accept, so you received ' + m(usdm) + ' instead.');
    else say('back', moved + 'your ' + u(tok) + ' ' + sym + ' is back in your wallet.');
  } else if (o.kind === 1) {
    title = 'Sell ' + u(o.x) + ' ' + sym;
    if (o.settled && usdm > 0n) say('paid', 'You received ' + m(usdm) + '.');
    else if (o.settled) say('back', moved + 'your ' + u(tok) + ' ' + sym + ' is back in your wallet.');
  } else if (o.kind === 2) {
    title = 'Add liquidity · ' + sym;
    if (o.settled && share > 0n) say('paid', 'You hold your part of the pool as shares in your wallet, yours to remove at any time.' + (tok > 0n || usdm > 0n ? ' What did not fit the pool\'s ratio came back: ' + both(tok, usdm) + '.' : ''));
    else if (o.settled) say('back', 'Your ' + both(tok, usdm) + ' came back whole: a launch curve takes no liquidity, and a first deposit must be more than dust.');
  } else if (o.kind === 3) {
    title = 'Remove liquidity · ' + sym + (fromDate ? ' (locked until ' + fromDate + ')' : '');
    if (o.settled && lockedBack > 0n) say('back', 'These shares are locked until ' + fromDate + ': they cannot leave the pool before that day, and are still yours, locked, in your wallet.');
    else if (o.settled && share > 0n) say('back', 'Those shares could not be taken out and are still yours, in your wallet.');
    else if (o.settled) say('paid', 'You received ' + both(tok, usdm) + '.');
  } else if (o.kind === 6) {
    title = (o.lock_from ? 'Extend a lock · ' : 'Lock liquidity · ') + sym + ' until ' + untilDate;
    if (o.settled && lockedNew > 0n) say('paid', 'Locked until ' + untilDate + '. The shares are in your wallet and keep earning; nobody can take that liquidity out before then.');
    else if (o.settled) say('back', 'The lock was not taken (its date was not a Monday after this week and within four years, or the pool had changed): your shares came back as they were.');
  } else if (o.kind === 7) {
    title = 'Unlock liquidity · ' + sym + ' (locked until ' + fromDate + ')';
    if (o.settled && share > 0n) say('paid', 'Unlocked: ordinary shares, yours to take out at any time.');
    else if (o.settled) say('back', 'Not unlocked yet: these shares are locked until ' + fromDate + ' and are still yours, locked, in your wallet.');
  } else if (o.kind === 4) {
    title = 'Launch ' + sym + ' on a curve';
    // a launch that opens the curve is paid nothing (the tokens are on the curve), so no note ever marks it paid
    if (tok > 0n) say('back', 'This token already had a pool or a curve, so your ' + u(tok) + ' ' + sym + ' came back.');
    else say('sent', 'On the curve once a block carries it. Your creator fees collect in the pool as people trade.');
  } else if (o.kind === 5) {
    title = 'Collect creator fees · ' + sym;
    if (o.settled) say('paid', 'You collected ' + both(tok, usdm) + '.');
  }
  return '<a class="item" href="#/pools?token=' + esc(o.token) + '">' + '<span class="coin">' + esc(String(sym).slice(0, 1).toUpperCase()) + '</span>' +
    // (the title wraps on a phone: "Swap 120 ORBIT for GLASS" cut to "Swap 120 ORBIT for …" hides the one word that matters)
    '<div class="t" style="white-space:normal">' + esc(title) + '</div><span class="chip ' + chip[0] + '">' + esc(chip[1]) + '</span><div class="s">' + esc(sub) + '</div></a>';
}
async function poolRows() {
  let r;
  try { r = await pl.orders(); } catch (_) { return []; } // hidden from this site, or a wallet that does not answer it: the rows above still show
  const out = [];
  for (const o of ((r && r.orders) || []).slice(0, SHOWN)) out.push(poolRow(o, await symbolOf(o.token), o.hop ? await symbolOf(o.hop) : ''));
  return out;
}

let alive = null;
export default async function render(view /* , ctx */) {
  const root = document.createElement('section');
  root.className = 'ion page';
  root.innerHTML = '<div><div class="eyebrow">Your swaps</div><h1>Activity</h1>' +
    '<p class="lead">What you have in flight, read from your own wallet. Nobody else is asked.</p></div>' +
    '<div id="ionActsLate" hidden></div>' +
    '<div class="list" id="ionActs"><div class="note">Reading your wallet…</div></div>';
  view.appendChild(root);
  alive = root;
  const list = root.querySelector('#ionActs'), late = root.querySelector('#ionActsLate');
  let shown = false; // a read has been painted: the cards on the page are the wallet's own answer
  let noteNow = ''; // the note the list shows in place of cards; written again only when its words change
  const note = (html) => { if (noteNow !== html) { list.innerHTML = html; noteNow = html; } };
  // THE PAGE READS ITS WALLET AGAIN EVERY SIX SECONDS AND REPAINTS IN PLACE (`paint`): a card whose words did not
  // change is not touched. Before, every read wrote the whole list again and every card rose in again: the flicker.
  // A read that FAILS after one that worked does not take the cards away (they came and went with every slow answer,
  // a second flicker): the cards stay, a line above them says the last read did not answer, and the next read clears
  // it. The one failure that does clear the cards at once is the person hiding their activity from this site.
  const tick = async () => {
    if (alive !== root || !root.isConnected) return; // the user moved on
    if (!S.wallet && !(await learn())) {
      late.hidden = true;
      note(connectNote('to see your swaps'));
      return;
    }
    try {
      const items = (await poolRows()).concat(rows(await ask('nativeProgress')));
      if (alive !== root || !root.isConnected) return;
      const dot = document.getElementById('activityDot');
      if (dot) dot.hidden = true;
      late.hidden = true;
      noteNow = '';
      paint(list, items, '<div class="note">Nothing in flight. Your next swap shows up here the moment your wallet starts it.</div>');
      shown = true;
    } catch (e) {
      if (alive !== root || !root.isConnected) return;
      if (shown && !isHidden(e)) {
        const words = 'Your wallet did not answer the last read (' + String((e && e.message) || e) + '). What is below is its answer from before; this page is asking again.';
        if (late.hidden || late.dataset.w !== words) { late.dataset.w = words; late.innerHTML = '<div class="note warn">' + esc(words) + '</div>'; late.hidden = false; }
      } else {
        late.hidden = true;
        shown = false;
        note(privateNote(e, 'swaps and activity'));
      }
    }
    setTimeout(tick, 6000);
  };
  tick();
}
