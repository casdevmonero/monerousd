// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// GOVERNANCE: the validator set, LIVE, as a chart (user 2026-11-10: one validator section, "with live validator
// stats chart"). One bar per validator, as tall as the SAT bonded behind it; this wallet's own node is the orange one.
// The figures are the chain's public ones, read through this wallet's own node while the page is open:
//
//   wallet_delegations   every validator and the SAT bonded behind it (the list the Delegate card already uses)
//   /validator_id        which of them this wallet's node is
//   wallet_my_bond       this node's uptime and whether it is on duty
//
// Nothing is drawn that was not read: with no answer the chart says so, and with no validators it says that. A bar
// that is tapped is chosen for delegating (it fills the Delegate card's validator box); nothing is sent by a tap.
//
// TWO-PARTY-REVIEWED: page presentation code, not a test; it builds no endpoint and moves no money.
'use strict';

(function () {
  const el = (id) => document.getElementById(id);
  const SHOWN = 40; // bars that fit a phone's width; the smallest validators past it are drawn together as one
  const fmt = (n, digits) => Number(n).toLocaleString(undefined, { maximumFractionDigits: digits == null ? 2 : digits });
  let busy = false;

  async function read() {
    const d = { validators: null, mine: '', bond: null, why: '' };
    try {
      const r = await walletCore('wallet_delegations');
      d.validators = ((r && r.validators) || []).map((v) => ({ id: String(v.validator || '').toLowerCase(), sat: Number(v.sat) || 0 })).filter((v) => v.id);
    } catch (e) { d.why = (e && e.notInApp) ? 'Open the MoneroUSD app to see the validator set.' : 'The validator set could not be read from your node.'; }
    try { const v = await nodeRpc('/validator_id'); d.mine = String((v && v.validator_id_hex) || '').toLowerCase(); } catch (_) { /* shown without the highlight */ }
    try { d.bond = await walletCore('wallet_my_bond'); } catch (_) { /* this node's own line is left out */ }
    return d;
  }

  function say(big, sub, share) {
    if (el('vxCount')) el('vxCount').textContent = big;
    if (el('vxSub')) el('vxSub').textContent = sub;
    if (el('vxShare')) el('vxShare').textContent = share || '';
  }

  // How few of the largest validators together hold more than a third of the bonded SAT: the smaller this is, the
  // more the set leans on a few.
  function thirdHeldBy(sorted, total) {
    let sum = 0;
    for (let i = 0; i < sorted.length; i++) { sum += sorted[i].sat; if (sum * 3 > total) return i + 1; }
    return sorted.length;
  }

  function draw(d) {
    const plot = el('vxPlot');
    if (!plot) return;
    const live = el('vxLive');
    if (d.validators === null) {
      plot.textContent = '';
      plot.setAttribute('data-empty', d.why);
      if (live) live.hidden = true;
      say('—', d.why, '');
      return;
    }
    if (live) live.hidden = false;
    const all = d.validators.slice().sort((a, b) => b.sat - a.sat);
    const total = all.reduce((s, v) => s + v.sat, 0);
    if (!all.length || !(total > 0)) {
      plot.textContent = '';
      plot.setAttribute('data-empty', 'No validator has bonded yet. The first bond appears here.');
      say('0 validators', 'Nobody has bonded SAT yet.', '');
      return;
    }
    plot.removeAttribute('data-empty');
    // the bars: the largest validators one each; past what fits, the rest together
    let bars = all.slice(0, SHOWN).map((v) => ({ key: v.id, sat: v.sat, label: v.id.slice(0, 10) + '…', id: v.id }));
    if (all.length > SHOWN) {
      const rest = all.slice(SHOWN - 1);
      bars = bars.slice(0, SHOWN - 1).concat([{ key: 'rest', sat: rest.reduce((s, v) => s + v.sat, 0), label: rest.length + ' smaller validators', id: '' }]);
    }
    const top = Math.max.apply(null, bars.map((b) => b.sat));
    const have = new Map([...plot.children].map((c) => [c.dataset.key, c]));
    const want = new Set(bars.map((b) => b.key));
    for (const [key, node] of have) if (!want.has(key)) node.remove();
    bars.forEach((b, i) => {
      let bar = have.get(b.key);
      if (!bar) {
        bar = document.createElement('button');
        bar.type = 'button';
        bar.className = 'vx-bar';
        bar.dataset.key = b.key;
        bar.style.height = '0%';
        bar.addEventListener('click', () => choose(bar));
      }
      // kept in order of size, so a validator that grows moves along the row
      if (plot.children[i] !== bar) plot.insertBefore(bar, plot.children[i] || null);
      const share = b.sat * 100 / total;
      bar.dataset.id = b.id;
      bar.dataset.say = b.label + ' · ' + fmt(b.sat, 8) + ' SAT · ' + fmt(share, 1) + '% of the bonded SAT';
      bar.title = bar.dataset.say;
      bar.setAttribute('aria-label', bar.dataset.say);
      bar.classList.toggle('me', !!d.mine && b.id === d.mine);
      const height = Math.max(3, b.sat * 100 / top);
      // set after the bar is in the page, so a new bar grows from the floor
      requestAnimationFrame(() => { bar.style.height = height.toFixed(2) + '%'; });
    });
    const k = thirdHeldBy(all, total);
    say(all.length + (all.length === 1 ? ' validator' : ' validators'),
      fmt(total, 2) + ' SAT bonded · the ' + (k === 1 ? 'largest holds' : k + ' largest hold') + ' a third of it');
    const mine = d.mine ? all.find((v) => v.id === d.mine) : null;
    const up = d.bond && d.bond.uptime_pct != null ? ' · uptime ' + d.bond.uptime_pct + '%' : '';
    const duty = d.bond && d.bond.retired ? ' · retired' : (d.bond && d.bond.drawn === true ? ' · on duty' : (d.bond && d.bond.drawn === false ? ' · resting' : ''));
    if (el('vxShare') && !el('vxShare').dataset.chosen) {
      el('vxShare').textContent = mine ? ('This node: ' + fmt(mine.sat, 8) + ' SAT · ' + fmt(mine.sat * 100 / total, 1) + '%' + up + duty) : 'This node is not a validator';
    }
  }

  // A tapped bar is the validator to delegate to: the Delegate card's box is filled, nothing is sent.
  function choose(bar) {
    const plot = el('vxPlot');
    for (const b of plot.children) b.classList.toggle('sel', b === bar && !bar.classList.contains('sel'));
    const on = bar.classList.contains('sel');
    const share = el('vxShare');
    if (share) {
      if (on) { share.dataset.chosen = '1'; share.textContent = bar.dataset.say + (bar.dataset.id ? ' · chosen for Delegate SAT below' : ''); }
      else { delete share.dataset.chosen; refresh(); }
    }
    const box = el('delegateValidator');
    if (box && bar.dataset.id) box.value = on ? bar.dataset.id : '';
  }

  async function refresh() {
    if (busy || !el('vxPlot')) return;
    busy = true;
    try { draw(await read()); } catch (_) { /* the next reading draws it */ }
    busy = false;
  }

  const showing = () => { const v = document.querySelector('.view[data-view="governance"]'); return !!v && v.classList.contains('active') && document.visibilityState === 'visible'; };

  document.addEventListener('DOMContentLoaded', () => {
    const view = document.querySelector('.view[data-view="governance"]');
    if (!view) return;
    // read when the page is opened, and every ten seconds while it is on screen
    new MutationObserver(() => { if (showing()) refresh(); }).observe(view, { attributes: true, attributeFilter: ['class'] });
    setInterval(() => { if (showing()) refresh(); }, 10000);
    document.addEventListener('visibilitychange', () => { if (showing()) refresh(); });
    if (showing()) refresh();
  });
})();
