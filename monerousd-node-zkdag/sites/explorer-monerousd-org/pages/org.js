// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// pages/org.js — one organization: who it is, what it ships, and the native assets it issues.

import { getOrg, NATIVE_ASSETS } from '../lib/registries.js';
import { escapeHtml as esc, goldCheckHTML, sanitizeHtml } from '../lib/helpers.js';
import { logoBox } from './common.js';

const SHIPS = {
  'monerousd-protocol': [
    ['The chain', 'Post-quantum, private block-DAG with GHOSTDAG ordering and WHIR proofs.', 'https://monerousd.org/#how'],
    ['The wallet', 'Pay, receive, tap to pay, earn and trade — with its own node inside.', 'https://monerousd.org/#wallet'],
    ['Letter', 'Sealed messages, groups and payments in chat.', 'https://monerousd.org/'],
    ['The Veil', 'MoneroUSD’s own mix network: no IP address is ever needed or findable.', 'https://monerousd.org/veil'],
    ['Sovereign', 'Sites and private back ends served from the chain.', 'https://monerousd.org/sovereign'],
    ['This explorer', 'Reads the chain from your own node.', '#/'],
  ],
  'ion-swap': [
    ['Swap', 'Native BTC, XMR, ETH, ZEC and SOL to USDm and back — the real coins, on their own chains.', 'https://ion.monerousd.org/#/swap'],
    ['Pools', 'Provide liquidity, lock it if you like, earn the pool’s fees.', 'https://ion.monerousd.org/#/pools'],
    ['Launch', 'Create a token with its supply and tokenomics shown from the start.', 'https://ion.monerousd.org/#/create'],
    ['NFT market', 'Collections, pieces and the creator studio.', 'https://ion.monerousd.org/#/market'],
  ],
};

export async function renderOrg({ view }, slug) {
  const org = getOrg(slug);
  if (!org) {
    view.innerHTML = `<div class="error-box"><strong>Unknown organization</strong><code>${esc(slug)}</code> — <a href="#/orgs">all organizations</a></div>`;
    return;
  }
  const assets = NATIVE_ASSETS.filter(a => a.org === slug);
  view.innerHTML = sanitizeHtml(`
    <header class="hero rv">
      <span class="kick">${esc(org.badges.join(' · '))}</span>
      <div class="detail-head" style="margin-top:14px">
        ${logoBox(org.logoUrl, org.name).replace('class="entity-logo"', 'class="entity-logo" style="width:72px;height:72px"')}
        <div><h1 style="margin:0;display:flex;align-items:center;gap:10px">${esc(org.name)} ${goldCheckHTML('xl')}</h1>
          <p style="margin-top:6px"><a href="${esc(org.website)}">${esc(org.website.replace(/^https:\/\//, ''))}</a></p></div>
      </div>
      <p style="margin-top:16px">${esc(org.blurb)}</p>
    </header>
    <section class="section"><div class="section-head rv"><div><span class="kick">Ships</span><h2>What ${esc(org.name)} builds</h2></div></div>
      <div class="explore-grid">${(SHIPS[slug] || []).map(([t, b, href], i) => `
        <a class="entity-card rv d${(i % 4) + 1}" href="${esc(href)}"><div class="entity-title">${esc(t)}</div><p class="entity-body">${esc(b)}</p><span class="go">Open →</span></a>`).join('')}
      </div></section>
    ${assets.length ? `<section class="section"><div class="section-head rv"><div><span class="kick">Issues</span><h2>Native assets</h2></div></div>
      <div class="explore-grid">${assets.map(a => `
        <a class="entity-card rv" href="#/token/${esc(a.symbol)}"><div class="entity-head">${logoBox(a.logoUrl, a.symbol, true)}
          <div><div class="entity-title">${esc(a.name)} ${goldCheckHTML()}</div><div class="entity-sub">${esc(a.symbol)}</div></div></div>
          <p class="entity-body">${esc(a.description)}</p><span class="go">Open →</span></a>`).join('')}</div></section>` : ''}
  `);
}
