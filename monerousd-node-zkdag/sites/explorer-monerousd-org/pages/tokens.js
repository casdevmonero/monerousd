// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// pages/tokens.js — the chain's tokens: the two native assets, then every token launched on the testnet, newest first,
// read from the directory the chain keeps. A token with a pool shows its clearing price (published once a batch) and
// its supply (public in its mint). Never a holder, a balance or a pool's depth.

import * as chain from '../lib/chain.js';
import { NATIVE_ASSETS } from '../lib/registries.js';
import { escapeHtml as esc, goldCheckHTML, isCloneAttempt, sanitizeHtml } from '../lib/helpers.js';
import { pageHead, connectPanel, logoBox, fmtPrice, fmtSupply } from './common.js';

export async function renderTokens({ ds, view }) {
  view.innerHTML = pageHead('Tokens', 'Every token on the chain',
    'The native dollar and SAT, and every token launched on the testnet — read from the directory the chain keeps. Holders and balances stay private.') + `
    <section class="section">
      <div class="section-head rv"><div><span class="kick">Native</span><h2>Built into the chain</h2></div></div>
      <div class="explore-grid">${NATIVE_ASSETS.map(nativeCard).join('')}</div>
    </section>
    <section class="section">
      <div class="section-head rv"><div><span class="kick">Launched</span><h2>Tokens on the testnet</h2>
        <p>Newest first. A launched token never gets the gold check; one that copies USDm or SAT is flagged.</p></div></div>
      <div id="tok-body"><div class="loading">Reading the chain’s directory…</div></div>
    </section>`;

  const body = view.querySelector('#tok-body');
  if (!(await ds.nodeReachable())) { body.innerHTML = connectPanel(); return; }

  let prices = new Map();
  try {
    const p = await chain.pools();
    for (const row of p.items) prices.set(row.token, row);
  } catch (_) { /* tokens still list without prices */ }

  const grid = document.createElement('div');
  grid.className = 'explore-grid';
  body.innerHTML = '';
  body.appendChild(grid);
  const more = document.createElement('div');
  more.style.marginTop = '18px';
  body.appendChild(more);

  let cursor = null, shown = 0;
  async function load() {
    more.innerHTML = '<div class="loading">Reading…</div>';
    let r;
    try { r = await chain.recentAssets('token', 24, cursor); }
    catch (e) { more.innerHTML = `<div class="error-box"><strong>The node did not answer</strong>${esc(e.message)}</div>`; return; }
    cursor = r.cursor;
    for (const t of r.items) {
      grid.insertAdjacentHTML('beforeend', sanitizeHtml(tokenCard(t, prices.get(t.id))));
      shown++;
      if (t.hasPic) chain.assetArt(t.id).then(url => paintArt(grid, t.id, url));
    }
    if (!shown) more.innerHTML = '<div class="empty-state"><div class="empty-state-title">No tokens launched yet</div><p class="muted">Launch one on IonSwap and it appears here as soon as a block carries it.</p></div>';
    else if (cursor != null) {
      more.innerHTML = '<button class="btn btn-ghost" id="tok-more">Load older tokens</button>';
      more.querySelector('#tok-more').addEventListener('click', load);
    } else more.innerHTML = `<p class="muted">${shown} token${shown === 1 ? '' : 's'} — that is every token on the chain.</p>`;
  }
  await load();
}

function paintArt(root, id, url) {
  if (!url) return;
  const box = root.querySelector(`[data-art="${id}"]`);
  if (box) box.innerHTML = `<img src="${url}" alt="">`;
}

function nativeCard(a) {
  return `<a class="entity-card rv" href="#/token/${encodeURIComponent(a.symbol)}">
    <div class="entity-head">${logoBox(a.logoUrl, a.symbol, true)}
      <div><div class="entity-title">${esc(a.name)} ${goldCheckHTML()}</div><div class="entity-sub">${esc(a.symbol)} · native</div></div></div>
    <p class="entity-body">${esc(a.description)}</p><span class="go">Open →</span></a>`;
}

function tokenCard(t, pool) {
  const clone = isCloneAttempt(t.symbol);
  return `<a class="entity-card" href="#/token/${encodeURIComponent(t.id)}">
    <div class="entity-head"><div class="entity-logo round" data-art="${esc(t.id)}"><span>${esc((t.symbol || '?').slice(0, 2).toUpperCase())}</span></div>
      <div><div class="entity-title">${esc(t.name || t.symbol)} ${clone ? '<span class="badge badge-warning">copies a native ticker</span>' : ''}</div>
        <div class="entity-sub">${esc(t.symbol)} · ${esc(t.id.slice(0, 10))}…</div></div></div>
    <div class="entity-meta">
      ${pool ? `<span class="badge badge-info">${esc(fmtPrice(pool.price_e12))} USDm</span>` : '<span class="badge badge-muted">no pool yet</span>'}
      ${pool && pool.supply != null ? `<span class="badge badge-muted">supply ${esc(fmtSupply(pool.supply))}</span>` : ''}
      ${pool && pool.lock ? `<span class="badge ${pool.lock.status === 'locked' ? 'badge-success' : 'badge-warning'}">liquidity ${esc(pool.lock.status)}</span>` : ''}
    </div><span class="go">Open →</span></a>`;
}
