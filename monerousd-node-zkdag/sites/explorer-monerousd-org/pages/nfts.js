// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// pages/nfts.js — NFT collections and pieces, from the chain's directory: a collection's title, words and cover, and
// each piece's picture, all kept by the chain itself. Owners stay private.

import * as chain from '../lib/chain.js';
import { escapeHtml as esc, sanitizeHtml } from '../lib/helpers.js';
import { pageHead, connectPanel } from './common.js';

export async function renderNfts({ ds, view }) {
  view.innerHTML = pageHead('NFTs', 'Collections and pieces',
    'Every NFT on the testnet, with the art the chain keeps for it. Who owns a piece stays private.') + `
    <section class="section"><div class="section-head rv"><div><span class="kick">Collections</span><h2>Newest collections</h2></div></div>
      <div id="col-body"><div class="loading">Reading the chain’s directory…</div></div></section>
    <section class="section"><div class="section-head rv"><div><span class="kick">Pieces</span><h2>Newest pieces</h2></div></div>
      <div id="nft-body"><div class="loading">Reading…</div></div></section>`;

  const colBody = view.querySelector('#col-body');
  const nftBody = view.querySelector('#nft-body');
  if (!(await ds.nodeReachable())) { colBody.innerHTML = connectPanel(); nftBody.innerHTML = ''; return; }

  try {
    const c = await chain.collections(0, 24);
    colBody.innerHTML = c.items.length ? `<div class="listing-grid">${c.items.map(col => `
      <a class="listing" href="https://ion.monerousd.org/#/nfts">
        <div class="entity-logo" data-cover="${esc(col.handle)}" style="width:100%;height:150px;border-radius:12px;font-size:28px"><span>${esc(col.title.slice(0, 2).toUpperCase())}</span></div>
        <div><div class="entity-title">${esc(col.title)}</div><div class="entity-sub">@${esc(col.handle)} · ${col.pieces} piece${col.pieces === 1 ? '' : 's'}</div></div>
        ${col.text ? `<p class="entity-body">${esc(col.text.slice(0, 140))}${col.text.length > 140 ? '…' : ''}</p>` : ''}
      </a>`).join('')}</div>` : emptyState('No collections yet', 'Create one in the IonSwap studio and it appears here when a block carries it.');
    colBody.innerHTML = sanitizeHtml(colBody.innerHTML);
    for (const col of c.items.filter(x => x.has_cover)) {
      chain.collection(col.handle).then(full => {
        const url = full && chain.hexToDataUrl(full.cover_mime, full.cover_hex);
        const box = colBody.querySelector(`[data-cover="${col.handle}"]`);
        if (url && box) box.innerHTML = `<img src="${url}" alt="" style="object-fit:cover;padding:0">`;
      }).catch(() => {});
    }
  } catch (e) { colBody.innerHTML = `<div class="error-box"><strong>The node did not answer</strong>${esc(e.message)}</div>`; }

  try {
    const r = await chain.recentAssets('nft', 24);
    nftBody.innerHTML = r.items.length ? sanitizeHtml(`<div class="listing-grid">${r.items.map(n => `
      <a class="listing" href="#/token/${esc(n.id)}">
        <div class="entity-logo" data-art="${esc(n.id)}" style="width:100%;height:170px;border-radius:12px;font-size:28px"><span>${esc((n.symbol || n.name || '?').slice(0, 2).toUpperCase())}</span></div>
        <div><div class="entity-title">${esc(n.name || n.symbol)}</div><div class="entity-sub">${esc(n.symbol)} · ${esc(n.id.slice(0, 10))}…</div></div>
      </a>`).join('')}</div>`) : emptyState('No NFTs minted yet', 'Mint one on IonSwap and it appears here.');
    for (const n of r.items.filter(x => x.hasPic)) {
      chain.assetArt(n.id).then(url => {
        const box = nftBody.querySelector(`[data-art="${n.id}"]`);
        if (url && box) box.innerHTML = `<img src="${url}" alt="" style="object-fit:cover;padding:0">`;
      });
    }
  } catch (e) { nftBody.innerHTML = `<div class="error-box"><strong>The node did not answer</strong>${esc(e.message)}</div>`; }
}

function emptyState(title, text) {
  return `<div class="empty-state"><div class="empty-state-title">${esc(title)}</div><p class="muted">${esc(text)}</p></div>`;
}
