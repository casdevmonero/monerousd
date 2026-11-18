// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// pages/block.js — one height of the block-DAG, or one block by its id. Read from the node's recent DAG (`/dag_recent`):
// each block's real id, its own timestamp, its parents and whether it is on the selected chain. A height holds one or
// more blocks (blocks are mined side by side). The node keeps no per-block history past its recent window, so an older
// height says that instead of inventing an id or a time. What a block carries is the same 256 padded slots every block
// carries: which are real payments, and their amounts and parties, are not on the chain.

import { escapeHtml as esc, sanitizeHtml } from '../lib/helpers.js';
import { timeAgo } from '../lib/data-source.js';
import { connectPanel } from './common.js';

export async function renderBlock({ ds, view }, idOrHeight) {
  if (!(await ds.nodeReachable())) { view.innerHTML = connectPanel(); return; }
  const q = String(idOrHeight).toLowerCase();
  const byId = /^[0-9a-f]{64}$/.test(q);
  if (!byId && !/^\d+$/.test(q)) {
    view.innerHTML = `<div class="error-box"><strong>Not a block</strong>Give a height or a 64-character block id.</div>`;
    return;
  }
  const [dag, info] = await Promise.all([ds.dagRecent().catch(() => []), ds.callDaemon('get_info').catch(() => null)]);
  const tip = Number(info?.height || 0), fin = Number(info?.finalized_height || 0);
  const ids = new Map(dag.map(b => [b.id, b]));
  const one = byId ? ids.get(q) : null;
  const height = byId ? (one ? Number(one.blue_score) : null) : Number(q);
  const here = height == null ? [] : dag.filter(b => Number(b.blue_score) === height).sort((a, b) => (b.selected - a.selected));
  const focus = one || here[0] || null;

  const head = `
    <header class="hero rv">
      <span class="kick">Block-DAG height</span>
      <h1>${height == null ? 'Block ' + esc(q.slice(0, 12)) + '…' : '#' + height.toLocaleString('en-US')}</h1>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px">
        ${height != null && height <= fin ? '<span class="badge badge-success">final</span>' : (height != null ? '<span class="badge badge-warning">not final yet</span>' : '')}
        ${height != null ? `<span class="badge">${Math.max(0, tip - height).toLocaleString('en-US')} blocks deep</span>` : ''}
        ${here.length > 1 ? `<span class="badge badge-info">${here.length} blocks at this height</span>` : ''}
      </div>
    </header>
    <div style="display:flex;gap:10px;margin:6px 0 4px">
      ${height > 0 ? `<a class="btn btn-ghost btn-sm" href="#/block/${height - 1}">← #${(height - 1).toLocaleString('en-US')}</a>` : ''}
      ${height != null && height < tip ? `<a class="btn btn-ghost btn-sm" href="#/block/${height + 1}">#${(height + 1).toLocaleString('en-US')} →</a>` : ''}
    </div>`;

  if (!focus) {
    view.innerHTML = sanitizeHtml(head + `
      <section class="card rv"><div class="empty-state"><div class="empty-state-title">Past your node’s recent window</div>
        <p class="muted">Your node keeps the recent block-DAG and a constant-size proof of everything before it, never a
          list of every old block. ${height != null && height <= fin ? 'This height is final: its blocks are folded into the chain’s proof.' : ''}</p></div></section>`);
    return;
  }

  const blocks = one ? [one] : here;
  view.innerHTML = sanitizeHtml(head + blocks.map(b => `
    <section class="card rv">
      <div class="card-header"><h2 style="font-size:16px;word-break:break-all"><a class="mono" href="#/block/${esc(b.id)}">${esc(b.id)}</a></h2>
        <span class="badge ${b.selected ? 'badge-success' : 'badge-muted'}">${b.selected ? 'selected chain' : 'merged'}</span></div>
      <dl class="kv-table">
        <dt>Block id</dt><dd class="mono copyable" data-copy="${esc(b.id)}">${esc(b.id)}</dd>
        <dt>Mined</dt><dd>${b.ts ? esc(new Date(Number(b.ts)).toUTCString()) + ' · ' + esc(timeAgo(Math.floor(Number(b.ts) / 1000))) : '—'}</dd>
        <dt>Blue score</dt><dd>${Number(b.blue_score).toLocaleString('en-US')}</dd>
        <dt>Parents</dt><dd>${(b.parents || []).length ? (b.parents || []).map(p => {
          const pb = ids.get(p);
          return `<a class="mono" href="#/block/${esc(p)}">${esc(p)}</a>${pb ? ` <span class="muted">· #${Number(pb.blue_score).toLocaleString('en-US')}${pb.selected ? ' · selected chain' : ''}</span>` : ' <span class="muted">· older than your node’s recent window</span>'}`;
        }).join('<br>') : '—'}</dd>
        <dt>Slots</dt><dd>256, like every block — which are real payments is not on the chain</dd>
      </dl>
    </section>`).join(''));
}
