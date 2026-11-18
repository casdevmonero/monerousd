// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// pages/home.js — the explorer's front page: the live hero (block-DAG backdrop, measured chain figures), the recent
// blocks right under it (refreshing while the page is open), the explore grid and the live-DAG view.
//
// Every figure is read from the reader's own node and is MEASURED there: height, final height, the block time over
// the node's recent DAG window, the tips at the frontier and the peers. Protocol constants are labelled as targets,
// never shown as measurements. With no node to read, the page says so and shows how to connect one.

import { timeAgo } from '../lib/data-source.js';
import { BRIDGE_COINS } from '../lib/registries.js';
import { sanitizeHtml, escapeHtml } from '../lib/helpers.js';

const PAGE_SIZE = 12;
const REFRESH_MS = 8000;
const anim = () => window.USDM_ANIM || { startDag: () => ({ pulse() {} }), countTo: (el, v) => { if (el) el.textContent = v; } };

const ICON = {
  tokens: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v10M9 9.5h4.5a1.75 1.75 0 010 3.5H9.5a1.75 1.75 0 000 3.5H15"/></svg>',
  nfts: '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="9" cy="9" r="1.6"/><path d="M3 16l5-5 4 4 3-3 6 6"/></svg>',
  names: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 006 0v-1a10 10 0 10-4 8"/></svg>',
  bridge: '<svg viewBox="0 0 24 24"><path d="M3 17h18M5 17V9a7 7 0 0114 0v8M9 17v-5M15 17v-5"/></svg>',
  validators: '<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
  sites: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"/></svg>',
  orgs: '<svg viewBox="0 0 24 24"><path d="M3 21V5a2 2 0 012-2h6v18M11 21V11h8a2 2 0 012 2v8M7 7h1M7 11h1M7 15h1M15 15h2"/></svg>',
  privacy: '<svg viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/></svg>',
  settle: '<svg viewBox="0 0 24 24"><path d="M4 7h11l-3-3M20 17H9l3 3"/></svg>',
};

function heroHTML() {
  return `
    <header class="hero home-hero">
      <canvas id="hero-dag" class="hero-dag-canvas" aria-hidden="true"></canvas>
      <div class="container">
        <span class="live-pill" id="hero-live"><i></i><span id="hero-live-text">Testnet · connecting to your node</span></span>
        <h1>Every block, in the open. <span class="or">Every payment, private.</span></h1>
        <p class="lead">The MoneroUSD block explorer reads the chain from your own node. You see the block-DAG, the proofs,
          the tokens, NFTs and @names people chose to publish — never an amount, a sender or a receiver.</p>
        <div class="hero-cta-row">
          <a class="hero-cta hero-cta-primary" href="#/names">Find a @name</a>
          <a class="hero-cta hero-cta-ghost" href="#/tokens">Browse tokens</a>
          <a class="hero-cta hero-cta-ghost" href="#" id="hero-dag-open">Watch the live DAG</a>
        </div>
        <div class="hero-pills">
          <span class="hero-pill"><span class="hero-pill-dot"></span>Hidden amounts &amp; parties</span>
          <span class="hero-pill"><span class="hero-pill-dot"></span>ML-KEM · ML-DSA · WHIR</span>
          <span class="hero-pill"><span class="hero-pill-dot"></span>GHOSTDAG block-DAG</span>
          <span class="hero-pill"><span class="hero-pill-dot"></span>No metadata leaks</span>
        </div>
        <div class="hero-stats" id="hero-stats">
          ${stat('height', 'Block height', 'blue score')}
          ${stat('final', 'Final height', 'settled, no reorg past it')}
          ${stat('btime', 'Block time', 'measured · target 0.5 s')}
          ${stat('tips', 'Open tips', 'blocks at the frontier now')}
          ${stat('peers', 'Peers', 'onion-only links')}
        </div>
      </div>
    </header>`;
}

function stat(key, label, sub) {
  return `<div class="hero-stat" data-stat="${key}"><div class="hero-stat-label">${label}</div>
    <div class="hero-stat-value" id="st-${key}"><span class="skel" style="width:70%;height:26px;margin-top:4px"></span></div>
    <div class="hero-stat-sub" id="st-${key}-sub">${sub}</div></div>`;
}

function connectHTML() {
  return `
    <section class="connect rv">
      <div>
        <span class="kick">No node connected</span>
        <h2>This explorer reads the chain from <span class="or">your own node</span>.</h2>
        <p>There is no MoneroUSD server to ask. A node answers only its own wallet and the pages it serves itself, so a
          public copy of this page cannot read anyone's node. Open the explorer one of these ways and every block,
          token and @name below fills in live.</p>
      </div>
      <ol>
        <li><span><strong>In the wallet:</strong> open Apps → Explorer. It reads the wallet's own node.</span></li>
        <li><span><strong>From your node:</strong> run a node and open <code>http://127.0.0.1:27752/explorer-monerousd-org/</code>.</span></li>
        <li><span><strong>New here?</strong> <a href="https://monerousd.org/testnet">Join the testnet</a> — the wallet sets up its node for you.</span></li>
      </ol>
    </section>`;
}

function blocksCardHTML() {
  return `
    <section class="card flush rv" id="blocks-card">
      <div class="card-header">
        <h2>Recent blocks</h2>
        <div class="card-action" id="blocks-action" title="Refresh now">Updating live</div>
      </div>
      <div id="blocks-body">${skeletonRows()}</div>
    </section>`;
}

function skeletonRows() {
  return `<div class="table-wrap"><table><tbody>${Array.from({ length: 6 }, () =>
    `<tr><td><span class="skel" style="width:80px"></span></td><td><span class="skel" style="width:60px"></span></td><td><span class="skel" style="width:240px"></span></td><td><span class="skel" style="width:40px"></span></td></tr>`).join('')}</tbody></table></div>`;
}

function exploreHTML() {
  const coins = BRIDGE_COINS.map(c => `<img src="${c.logoUrl}" alt="${c.symbol}" title="${c.name}" width="22" height="22" style="width:22px;height:22px">`).join('');
  const card = (href, icon, title, sub, body, extra = '', d = '') => `
    <a class="entity-card rv ${d}" href="${href}">
      <div class="entity-head"><div class="entity-logo">${icon}</div>
        <div><div class="entity-title">${title}</div><div class="entity-sub">${sub}</div></div></div>
      <p class="entity-body">${body}</p>${extra}
      <span class="go">Open →</span>
    </a>`;
  return `
    <section class="section">
      <div class="section-head rv">
        <div><span class="kick">Explore</span><h2>Everything the chain makes public</h2>
          <p>What creators and owners chose to publish, read straight from the chain's directory.</p></div>
      </div>
      <div class="explore-grid">
        ${card('#/tokens', ICON.tokens, 'Tokens', 'USDm · SAT · launched tokens', 'The native dollar and SAT, and every token launched on the testnet, with its supply and pool.', '', 'd1')}
        ${card('#/nfts', ICON.nfts, 'NFTs', 'collections · pieces', 'Collections and pieces, with the art the chain itself keeps for them.', '', 'd2')}
        ${card('#/names', ICON.names, '@names', 'claim · buy · sell', 'Look up any @name, see what it costs, claim it or buy one that is for sale.', '', 'd3')}
        ${card('https://ion.monerousd.org', ICON.bridge, 'Bridge', 'native swaps', 'BTC, XMR, ETH, ZEC and SOL swap straight to USDm — the real coins, held in vaults on their own chains.',
          `<div style="display:flex;gap:6px;align-items:center">${coins}</div>`, 'd4')}
        ${card('#/validators', ICON.validators, 'Validators', 'bonded set', 'What it costs to take over custody, from the node’s own bond figures.', '', 'd1')}
        ${card('#/l2', ICON.settle, 'Settlements', 'PQ notes', 'Post-quantum note settlements and the roots they move — values stay hidden.', '', 'd2')}
        ${card('#/sites', ICON.sites, 'Sovereign sites', '.mud hosting', 'Sites served from the chain, hash-checked by every node that serves them.', '', 'd3')}
        ${card('#/orgs', ICON.orgs, 'Organizations', 'who builds it', 'The teams building on MoneroUSD and what they publish.', '', 'd4')}
      </div>
    </section>`;
}

function concealedHTML() {
  return `
    <section class="section">
      <div class="section-head rv"><div><span class="kick">Digital cash</span><h2>What you will never see here</h2>
        <p>An explorer on most chains is a surveillance tool. This one cannot be: the chain does not hold the data.</p></div></div>
      <div class="privacy-grid">
        <div class="privacy-col rv d1"><h3><span class="privacy-pill concealed">Concealed</span></h3><ul class="privacy-list">
          <li>Every amount, sender and receiver</li><li>How many payments a block really carries — every block is padded to the same 256 slots</li>
          <li>Which notes are spent, and by whom</li><li>Who holds a token, an NFT or a balance</li></ul></div>
        <div class="privacy-col rv d2"><h3><span class="privacy-pill public">Public</span></h3><ul class="privacy-list">
          <li>Blocks, their parents and their proofs</li><li>Assets, collections and @names their owners chose to publish</li>
          <li>Each pool's clearing price once a batch</li><li>Protocol-wide totals, never per-person figures</li></ul></div>
      </div>
    </section>`;
}

function dagShowcaseHTML() {
  return `
    <section class="dag-showcase rv">
      <canvas id="showcase-dag" aria-hidden="true"></canvas>
      <span class="kick">Live</span>
      <h2>Watch the block-DAG grow</h2>
      <p>Blocks from many producers land side by side and GHOSTDAG orders them, so the chain keeps going while
        blocks are mined in parallel. Open the 3D view to see your node's DAG as it arrives.</p>
      <a class="btn btn-primary dag-showcase-cta" href="#" id="dag-view-toggle">Open the live DAG</a>
    </section>`;
}

export async function renderHome(ctx) {
  const { ds, view } = ctx;
  view.innerHTML = heroHTML() + `<div id="home-main">${blocksCardHTML()}</div>` + exploreHTML() + concealedHTML() + dagShowcaseHTML();

  const A = anim();
  const heroDag = A.startDag(view.querySelector('#hero-dag'));
  A.startDag(view.querySelector('#showcase-dag'), { step: 96, speed: 0.02 });

  const openDag = (e) => {
    e.preventDefault();
    const btn = document.querySelector('.ev-seg button[data-ev="dag"]');
    if (btn) btn.click();
  };
  view.querySelector('#dag-view-toggle')?.addEventListener('click', openDag);
  view.querySelector('#hero-dag-open')?.addEventListener('click', openDag);

  const live = view.querySelector('#hero-live');
  const liveText = view.querySelector('#hero-live-text');
  if (!(await ds.nodeReachable())) {
    live.classList.add('off');
    liveText.textContent = 'Testnet · no node connected';
    for (const k of ['height', 'final', 'btime', 'tips', 'peers']) {
      const el = view.querySelector('#st-' + k);
      if (el) el.textContent = '—';
    }
    view.querySelector('#home-main').innerHTML = connectHTML();
    for (const id of ['#dag-view-toggle', '#hero-dag-open']) {
      const b = view.querySelector(id);
      if (b) { b.textContent = 'Live DAG needs a node'; b.setAttribute('aria-disabled', 'true'); b.style.opacity = '.5'; b.style.pointerEvents = 'none'; }
    }
    return;
  }
  liveText.textContent = 'Testnet live · reading ' + ds.getActiveSourceLabel();

  const state = { top: null, follow: true, lastTip: -1 };
  view.querySelector('#blocks-action')?.addEventListener('click', () => { state.follow = true; state.top = null; tick(); });

  async function tick() {
    if (!view.isConnected || !document.getElementById('hero-stats')) return false;
    let info = null;
    try { info = await ds.callDaemon('get_info'); } catch (_) { /* this tick only */ }
    let dag = [];
    try { dag = await ds.dagRecent(); } catch (_) {}
    if (info) paintStats(view, info, dag);
    const tip = Number(info?.height || 0);
    if (state.follow || state.top == null) state.top = Math.max(0, tip);
    const fresh = state.lastTip >= 0 && tip > state.lastTip;
    if (fresh) heroDag.pulse();
    paintBlocks(view, ds, dag, state, tip, fresh ? state.lastTip : null);
    state.lastTip = tip;
    return true;
  }

  await tick();
  const timer = setInterval(async () => { if (!(await tick())) clearInterval(timer); }, REFRESH_MS);
  window.addEventListener('hashchange', () => clearInterval(timer), { once: true });
}

function paintStats(view, info, dag) {
  const A = anim();
  const set = (k, v, fmt) => { const el = view.querySelector('#st-' + k); if (!el) return; if (v == null || !isFinite(v)) { el.textContent = '—'; return; } A.countTo(el, v, fmt); };
  set('height', Number(info.height));
  set('final', Number(info.finalized_height));
  set('tips', Number(info.tips));
  set('peers', Number(info.peers));
  const bt = measuredBlockTime(dag);
  set('btime', bt && bt.sec, n => (n >= 10 ? n.toFixed(0) : n.toFixed(1)) + ' s');
  const sub = view.querySelector('#st-btime-sub');
  if (sub) sub.textContent = bt == null ? 'not enough recent blocks' : 'over the last ' + bt.window + ' blocks · target 0.5 s';
  view.querySelectorAll('.hero-stat').forEach(s => { s.classList.add('tick'); setTimeout(() => s.classList.remove('tick'), 900); });
}

// /dag_recent stamps blocks in milliseconds.
const secs = (ts) => Math.floor(Number(ts) / 1000);

// Seconds per blue-score step across the node's recent DAG window: the time the window spans divided by the scores it
// climbs. Measured from the blocks' own timestamps; `null` when the window holds fewer than two scores.
function measuredBlockTime(dag) {
  const by = new Map();
  for (const b of dag || []) {
    const s = Number(b.blue_score), t = Number(b.ts);
    if (!isFinite(s) || !isFinite(t) || t <= 0) continue;
    if (!by.has(s) || by.get(s) > t) by.set(s, t);
  }
  const scores = [...by.keys()].sort((a, b) => a - b);
  if (scores.length < 2) return null;
  const lo = scores[0], hi = scores[scores.length - 1];
  const span = by.get(hi) - by.get(lo);
  if (span <= 0) return null;
  return { sec: span / 1000 / (hi - lo), window: hi - lo };
}

function paintBlocks(view, ds, dag, state, tip, prevTip) {
  const body = view.querySelector('#blocks-body');
  if (!body) return;
  const byScore = new Map();
  for (const d of dag || []) {
    const s = Number(d.blue_score);
    if (!byScore.has(s)) byScore.set(s, []);
    byScore.get(s).push(d);
  }
  const top = state.top;
  const rows = [];
  for (let h = top; h > top - PAGE_SIZE && h >= 0; h--) {
    const blocks = byScore.get(h) || [];
    const lead = blocks.find(b => b.selected) || blocks[0];
    const isNew = prevTip != null && h > prevTip;
    rows.push(`<tr class="${isNew ? 'fresh' : ''}">
      <td><span class="blk-dot"></span><a href="#/block/${h}">${h.toLocaleString('en-US')}</a></td>
      <td>${lead && lead.ts ? escapeHtml(timeAgo(secs(lead.ts))) : '<span class="muted">—</span>'}</td>
      <td>${lead ? `<a class="mono" href="#/block/${encodeURIComponent(lead.id)}" title="${escapeHtml(lead.id)}">${escapeHtml(lead.id.slice(0, 20))}…</a>`
        : '<span class="muted" title="beyond this node’s recent window; the node keeps no per-block history past it">beyond the recent window</span>'}</td>
      <td class="num">${blocks.length ? blocks.length + (blocks.length === 1 ? ' block' : ' blocks') : '—'}</td>
      <td class="num">${lead ? (lead.parents || []).length : '—'}</td>
    </tr>`);
  }
  const newestShown = top >= tip;
  body.innerHTML = sanitizeHtml(`
    <div class="table-wrap"><table>
      <thead><tr><th>Height</th><th>Age</th><th>Block</th><th class="num">At this height</th><th class="num">Parents</th></tr></thead>
      <tbody>${rows.join('')}</tbody></table></div>
    <div class="pager">
      <button class="btn btn-ghost btn-sm" id="newer-btn" ${newestShown ? 'disabled' : ''}>← Newer</button>
      <span class="pager-info">Blocks ${Math.max(0, top - PAGE_SIZE + 1).toLocaleString('en-US')} – ${top.toLocaleString('en-US')}${newestShown ? ' · live' : ''}</span>
      <button class="btn btn-ghost btn-sm" id="older-btn" ${top - PAGE_SIZE < 0 ? 'disabled' : ''}>Older →</button>
    </div>`);
  const action = view.querySelector('#blocks-action');
  if (action) action.textContent = state.follow ? 'Updating live' : 'Paused · click to follow the tip';
  body.querySelector('#older-btn')?.addEventListener('click', () => { state.follow = false; state.top = Math.max(0, top - PAGE_SIZE); paintBlocks(view, ds, dag, state, tip, null); });
  body.querySelector('#newer-btn')?.addEventListener('click', () => {
    state.top = Math.min(tip, top + PAGE_SIZE);
    state.follow = state.top >= tip;
    paintBlocks(view, ds, dag, state, tip, null);
  });
}
