// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// pages/orgs.js — the organizations building MoneroUSD, with their own logos (served beside this page).

import { VERIFIED_ORGS } from '../lib/registries.js';
import { escapeHtml as esc, goldCheckHTML, sanitizeHtml } from '../lib/helpers.js';
import { pageHead, logoBox } from './common.js';

export async function renderOrgs({ view }) {
  view.innerHTML = sanitizeHtml(pageHead('Organizations', 'Who builds MoneroUSD',
    'The teams behind the chain and its apps. Anyone can publish on the chain; the gold check marks the genuine teams.') + `
    <section class="section"><div class="explore-grid">
      ${VERIFIED_ORGS.map((o, i) => `
        <a class="entity-card rv d${i + 1}" href="#/org/${encodeURIComponent(o.slug)}">
          <div class="entity-head">${logoBox(o.logoUrl, o.name)}
            <div><div class="entity-title">${esc(o.name)} ${goldCheckHTML()}</div><div class="entity-sub">${esc(o.website.replace(/^https:\/\//, ''))}</div></div></div>
          <p class="entity-body">${esc(o.blurb)}</p>
          <div class="entity-meta">${o.badges.map(b => `<span class="badge badge-muted">${esc(b)}</span>`).join('')}</div>
          <span class="go">Open →</span>
        </a>`).join('')}
    </div></section>`);
}
