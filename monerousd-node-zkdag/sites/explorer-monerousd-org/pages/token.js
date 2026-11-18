// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// pages/token.js — one token: a native asset by its symbol (USDm, SAT), or a launched token or NFT by its chain id,
// with what the chain records for it (name, picture, creator id, collection, supply) and its pool's clearing price.

import * as chain from '../lib/chain.js';
import { NATIVE_ASSETS } from '../lib/registries.js';
import { escapeHtml as esc, goldCheckHTML, isCloneAttempt, sanitizeHtml } from '../lib/helpers.js';
import { connectPanel, logoBox, fmtPrice, fmtSupply } from './common.js';

export async function renderToken({ ds, view }, idOrSymbol) {
  const native = NATIVE_ASSETS.find(a => a.symbol.toLowerCase() === String(idOrSymbol).toLowerCase());
  if (native) { view.innerHTML = sanitizeHtml(nativeHTML(native)); return; }

  if (!/^[0-9a-f]{64}$/i.test(String(idOrSymbol))) {
    view.innerHTML = `<div class="error-box"><strong>Not a token id</strong>A launched token is named by its 64-character chain id. <a href="#/tokens">All tokens →</a></div>`;
    return;
  }
  if (!(await ds.nodeReachable())) { view.innerHTML = connectPanel(); return; }

  const id = String(idOrSymbol).toLowerCase();
  const [a, poolR] = await Promise.all([chain.asset(id).catch(() => null), ds.nodeGet('/ion/pool', { token: id }).catch(() => null)]);
  if (!a) {
    view.innerHTML = `<div class="error-box"><strong>No such token on this chain</strong>Your node’s directory has no asset with id <code>${esc(id.slice(0, 16))}…</code>. <a href="#/tokens">All tokens →</a></div>`;
    return;
  }
  const pool = poolR && poolR.found ? poolR.pool : null;
  const clone = isCloneAttempt(a.symbol);
  const supply = a.supply != null ? a.supply : (pool && pool.supply);
  view.innerHTML = sanitizeHtml(`
    <header class="hero rv">
      <span class="kick">${a.kind === 'nft' ? 'NFT' : 'Token'} · launched on the testnet</span>
      <div class="detail-head" style="margin-top:14px">
        <div class="entity-logo round" id="tok-art" style="width:72px;height:72px;font-size:22px"><span>${esc((a.symbol || '?').slice(0, 2).toUpperCase())}</span></div>
        <div><h1 style="margin:0">${esc(a.name || a.symbol)}</h1>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px"><span class="badge">${esc(a.symbol)}</span>
          ${clone ? '<span class="badge badge-warning">copies a native ticker — not the real one</span>' : ''}
          ${pool && pool.lock ? `<span class="badge ${pool.lock.status === 'locked' ? 'badge-success' : 'badge-warning'}">liquidity ${esc(pool.lock.status)}</span>` : ''}</div></div>
      </div>
    </header>
    <section class="stat-grid">
      <div class="stat-tile rv d1"><div class="stat-tile-label">Price</div><div class="stat-tile-value">${pool ? esc(fmtPrice(pool.price_e12)) : '—'}</div><div class="stat-tile-sub">${pool ? 'USDm · last batch’s clearing price' : 'no pool yet'}</div></div>
      <div class="stat-tile rv d2"><div class="stat-tile-label">Supply</div><div class="stat-tile-value">${supply != null ? esc(fmtSupply(supply)) : '—'}</div><div class="stat-tile-sub">${supply != null ? 'minted once, public in its mint' : 'not minted yet'}</div></div>
      <div class="stat-tile rv d3"><div class="stat-tile-label">Kind</div><div class="stat-tile-value" style="font-size:20px">${a.kind === 'nft' ? 'NFT' : 'Token'}</div><div class="stat-tile-sub">${a.collection ? 'in @' + esc(a.collection) : 'no collection'}</div></div>
    </section>
    <section class="card rv">
      <div class="card-header"><h2>What the chain records</h2></div>
      <dl class="kv-table">
        <dt>Token id</dt><dd class="mono copyable" data-copy="${esc(a.id)}">${esc(a.id)}</dd>
        <dt>Note tag</dt><dd class="mono">${esc(a.tag)}</dd>
        <dt>Creator id</dt><dd class="mono">${esc(a.creator)}</dd>
        <dt>Picture</dt><dd>${a.has_art ? 'Kept on the chain (its digest is bound into the token’s id)' : 'None on the chain'}</dd>
        ${pool ? `<dt>Trading fee</dt><dd>${(Number(pool.fee && pool.fee.total_bps) / 100).toFixed(2)}% per trade, as the chain charges it</dd>` : ''}
      </dl>
    </section>
    <p class="hint">Who holds it and how much stays private: notes carry the token’s tag, never an owner.
      <a href="https://ion.monerousd.org/#/${a.kind === 'nft' ? 'market?a=' + esc(a.id) : 'token?t=' + esc(a.tag)}">${a.kind === 'nft' ? 'See it on the IonSwap market →' : 'Trade on IonSwap →'}</a></p>`);
  if (a.has_art) chain.assetArt(id).then(url => { const box = view.querySelector('#tok-art'); if (url && box) box.innerHTML = `<img src="${url}" alt="">`; });
}

function nativeHTML(a) {
  return `
    <header class="hero rv">
      <span class="kick">Native asset</span>
      <div class="detail-head" style="margin-top:14px">
        ${logoBox(a.logoUrl, a.symbol, true).replace('class="entity-logo round"', 'class="entity-logo round" style="width:72px;height:72px"')}
        <div><h1 style="margin:0;display:flex;align-items:center;gap:10px">${esc(a.name)} ${goldCheckHTML('xl')}</h1>
          <div style="margin-top:8px"><span class="badge">${esc(a.symbol)}</span> <span class="badge badge-success">built into the chain</span></div></div>
      </div>
      <p style="margin-top:18px">${esc(a.description)}</p>
    </header>
    <section class="card rv">
      <div class="card-header"><h2>Privacy</h2></div>
      <p>Every ${esc(a.symbol)} note hides its amount and its owner. The chain proves that nothing was created from
        nothing on every block, without ever learning who paid whom or how much. That is why this page shows no holders,
        no balances and no transfers: the chain does not have them.</p>
      <p style="margin-top:12px"><a href="#/privacy">What the chain conceals →</a></p>
    </section>`;
}
