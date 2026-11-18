// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// pages/search.js — /q/<query>: a block height opens the block; 64 hex opens the token with that id if the chain's
// directory has one, else the block with that id; an @name opens the name; anything else is matched against the
// search index (native assets, launched tokens and NFTs, organizations, sites).

import * as chain from '../lib/chain.js';
import { searchLocal } from '../lib/search-index.js';
import { escapeHtml as esc, sanitizeHtml } from '../lib/helpers.js';
import { pageHead } from './common.js';

export async function renderSearch({ ds, navigate, view }, rawQuery) {
  const q = String(rawQuery || '').trim();
  if (/^\d{1,12}$/.test(q)) { navigate('#/block/' + q); return; }
  if (/^@/.test(q)) { navigate('#/names/' + encodeURIComponent(chain.canonName(q))); return; }
  if (/^[0-9a-f]{64}$/i.test(q)) {
    const a = (await ds.nodeReachable()) ? await chain.asset(q.toLowerCase()).catch(() => null) : null;
    navigate((a ? '#/token/' : '#/block/') + q.toLowerCase());
    return;
  }

  const hits = searchLocal(q, 24).filter(e => e.kind !== 'tx' && e.kind !== 'block');
  view.innerHTML = sanitizeHtml(pageHead('Search', '“' + q + '”', hits.length ? '' : 'Nothing on the chain matches that yet.') + `
    <section class="section">
      ${hits.length ? `<div class="token-results">${hits.map(e => `
        <a class="token-result-card" href="${esc(e.href)}">
          <div class="token-result-logo">${e.logo ? `<img src="${esc(e.logo)}" alt="" data-initials="${esc((e.label || '?').slice(0, 2).toUpperCase())}">` : `<span>${esc(e.iconGlyph || (e.label || '?').slice(0, 2).toUpperCase())}</span>`}</div>
          <div class="token-result-info"><div class="token-result-name">${esc(e.label)}</div>
            <div class="token-result-meta"><span class="token-result-sym">${esc(e.symbol || '')}</span><span>${esc(e.sub || '')}</span></div></div>
          <div class="token-result-arrow">→</div>
        </a>`).join('')}</div>` : `
      <div class="card"><h3>What you can search</h3><ul class="privacy-list">
        <li>A block height, or a block’s 64-character id</li>
        <li>A token’s or NFT’s 64-character id, its symbol or its name</li>
        <li>An @name</li>
        <li>An organization or a sovereign site</li></ul>
        <p class="hint">Payments, amounts and owners cannot be searched: the chain does not hold them.</p></div>`}
    </section>`);
}
