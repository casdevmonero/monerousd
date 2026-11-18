// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/**
 * MoneroUSD Installers · Sovereign frontend.
 *
 * Reads the offline manifest shipped with the wallet bundle (T1 fallback)
 * and overlays it with the live indexer copy when reachable. This is a
 * pure-frontend SPA — every byte under this site is signed by the
 * official publisher's stealth key and verified by the SW-1 hash gate
 * before render.
 *
 * Wallet integration (`services/site-updater.js`) reads the SAME
 * manifest.json out-of-band when checking for upgrades; the page is
 * the human-readable mirror of that machinery.
 */
(function () {
  'use strict';

  const T1_MANIFEST = '_offline-api/v1/manifest.json';
  // Live manifest: prefer the sovereign-server's `/v1/*` proxy when the
  // page is loaded at `localhost:27752` (multi-operator failover + Tor
  // routing handled centrally), fall back to the configured indexer
  // endpoint when loaded directly (devs running this bundle off a
  // clearnet origin for testing).
  const LIVE_MANIFEST = (function () {
    try {
      const sovereign = /^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(location.hostname);
      if (sovereign) {
        // Same-origin request — sovereign-server proxies /v1/* upstream.
        return '/v1/sites/installers.monerousd.org/manifest';
      }
      return (localStorage.getItem('indexer_endpoint') || 'https://ion.monerousd.org')
        + '/v1/sites/installers.monerousd.org/manifest';
    } catch (_) {
      return 'https://ion.monerousd.org/v1/sites/installers.monerousd.org/manifest';
    }
  })();

  function fmtSize(b) {
    if (b == null) return '—';
    const n = Number(b) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(2) + ' MB';
    return (n / 1073741824).toFixed(2) + ' GB';
  }
  function shortHash(h) {
    if (!h) return '—';
    const s = String(h);
    if (s.length <= 14) return s;
    return s.slice(0, 8) + '…' + s.slice(-4);
  }
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  async function fetchJson(url) {
    try {
      const r = await fetch(url, { cache: 'no-store' });
      if (!r.ok) return null;
      return await r.json();
    } catch (_) { return null; }
  }

  function renderManifest(m) {
    if (!m) m = {};
    const versionEl = document.getElementById('rel-version');
    const channelEl = document.getElementById('rel-channel');
    const pubEl = document.getElementById('rel-published');
    const hashEl = document.getElementById('rel-roothash');
    if (versionEl) versionEl.textContent = m.version || '—';
    if (channelEl) channelEl.textContent = m.channel || 'stable';
    if (pubEl) {
      pubEl.textContent = m.publishedAt
        ? new Date(m.publishedAt).toLocaleString()
        : '—';
    }
    if (hashEl) hashEl.innerHTML = '<code>' + esc(shortHash(m.rootHash)) + '</code>';

    const body = document.getElementById('platforms-body');
    if (!body) return;
    const platforms = (m.platforms || []).filter(Boolean);
    if (platforms.length === 0) {
      body.innerHTML = '<tr><td colspan="4" class="muted">No release manifest yet — release pipeline has not published a SITE_PUBLISH for installers.monerousd.org.</td></tr>';
      return;
    }
    body.innerHTML = platforms.map((p) => {
      const platform = esc(p.platform || '—');
      const arch = esc(p.arch || '—');
      const size = esc(fmtSize(p.size));
      const sha = esc(shortHash(p.sha256));
      return '<tr>' +
        '<td>' + platform + '</td>' +
        '<td><code>' + arch + '</code></td>' +
        '<td>' + size + '</td>' +
        '<td><code>' + sha + '</code></td>' +
        '</tr>';
    }).join('');
  }

  async function init() {
    // T1 (shipped) manifest first so users on a fresh install see something
    // even with no network. Then upgrade to live if the indexer responds.
    const offline = await fetchJson(T1_MANIFEST);
    renderManifest(offline);
    const live = await fetchJson(LIVE_MANIFEST);
    if (live && live.version) renderManifest(live);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
