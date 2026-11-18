// Copyright (c) 2026, The MoneroUSD Protocol
//
// This file is an original work of the MoneroUSD Protocol — a post-quantum,
// GHOSTDAG block-DAG, zero-knowledge confidential-value protocol. It is NOT part
// of the Monero Project. Licensed under the Business Source License 1.1
// (SPDX-License-Identifier: BUSL-1.1); see the LICENSE file in this directory;
// Apache-2.0 from 2029-12-01.
//
// 4. ATTRIBUTION AND DISPLAY: any product, fork, service, or derivative work that
//    uses this software must retain and prominently display the MoneroUSD Protocol
//    License and must credit "The MoneroUSD Protocol" as the origin.

// js/offline-cache.js — sovereign-mirror API router (SW Phase 3)
//
// Injected as the FIRST <script> in every sovereign site's index.html, BEFORE
// any client lib (swap-client.js, token-client.js, explorer.js, …) reaches for
// window.fetch. It wraps fetch so that every same-origin /api/… and /v1/… call
// the app makes is served — in priority order — from:
//
//   1) LIVE, ON THE NODE: the same-origin request passes straight through to the
//      local sovereign server (127.0.0.1:27752), which reverse-proxies /api + /v1
//      to THIS node's live backend (daemon RPC + local sovereign services). So a
//      sovereign app is FULLY FUNCTIONAL self-hosted on the node — no VPS needed.
//      A successful GET is cached to localStorage for offline replay.
//   2) CACHE: the last good live GET response from localStorage, when the live
//      backend is momentarily unreachable.
//   3) BUNDLE: the Tier-1 fallback JSON shipped inside the wallet binary at
//      _offline-api/<path>.json (baseline data; the file is chain-anchored under
//      SITE_PUBLISH so it can't be tampered).
//   4) FAIL LOUD: a real 503 JSON error (never a silent hang or a masked 0),
//      so the app can render an explicit "offline" state.
//
// Static assets (js/css/img/wasm) are NEVER intercepted — they pass through
// untouched to the sovereign server's DA-verified file serving.
(function () {
  'use strict';
  if (window.__sovOfflineCacheInstalled) return;
  window.__sovOfflineCacheInstalled = true;

  var API_RE = /^\/(?:api|v1)\//;               // same-origin API namespaces only
  var LS_PREFIX = 'sov-api-cache:';
  var origFetch = window.fetch ? window.fetch.bind(window) : null;
  if (!origFetch) return;                        // no fetch → nothing to wrap

  function reqUrl(input) {
    if (typeof input === 'string') return input;
    if (input && typeof input.url === 'string') return input.url;
    return '';
  }
  function reqMethod(input, init) {
    if (init && init.method) return String(init.method).toUpperCase();
    if (input && input.method) return String(input.method).toUpperCase();
    return 'GET';
  }
  function isApi(u) {
    return u && u.origin === location.origin && API_RE.test(u.pathname);
  }
  // GET /api/tokens/verified → _offline-api/api/tokens/verified.json (params dropped)
  function bundlePath(pathname) {
    return '_offline-api' + pathname.replace(/\/+$/, '') + '.json';
  }
  function jsonResponse(bodyText, status, source) {
    return new Response(bodyText, {
      status: status,
      headers: { 'Content-Type': 'application/json', 'X-Sov-Source': source }
    });
  }
  async function fromBundle(pathname) {
    try {
      var r = await origFetch(bundlePath(pathname), { cache: 'no-store' });
      if (!r || !r.ok) return null;
      var data = await r.json();
      // Envelope {status,body} for non-200 fallbacks; otherwise a raw body.
      if (data && typeof data === 'object' && 'status' in data && 'body' in data) {
        return jsonResponse(JSON.stringify(data.body), Number(data.status) || 200, 'bundle');
      }
      return jsonResponse(JSON.stringify(data), 200, 'bundle');
    } catch (_) { return null; }
  }

  window.fetch = async function (input, init) {
    var raw = reqUrl(input);
    var u;
    try { u = new URL(raw, location.href); } catch (_) { return origFetch(input, init); }
    if (!isApi(u)) return origFetch(input, init);       // static / cross-origin → passthrough

    var method = reqMethod(input, init);
    var key = LS_PREFIX + u.pathname;

    // 1) LIVE — hit the node's own backend via the same-origin sovereign server.
    try {
      var live = await origFetch(input, init);
      if (live && live.ok) {
        if (method === 'GET') {
          try { localStorage.setItem(key, await live.clone().text()); } catch (_) {}
        }
        return live;
      }
      // A live non-OK on a non-GET (e.g. a rejected swap) is authoritative — return it.
      if (method !== 'GET') return live;
      // A live non-OK GET → fall through to cache/bundle so the UI still paints.
    } catch (_) { /* live backend unreachable → degrade */ }

    // 2) CACHE — last good live GET.
    if (method === 'GET') {
      try {
        var cached = localStorage.getItem(key);
        if (cached != null) return jsonResponse(cached, 200, 'cache');
      } catch (_) {}
      // 3) BUNDLE — Tier-1 shipped fallback.
      var bundled = await fromBundle(u.pathname);
      if (bundled) return bundled;
    }

    // 4) FAIL LOUD.
    return jsonResponse(JSON.stringify({
      error: 'sovereign offline', detail: 'no live node backend, no cache, no bundle for ' + u.pathname
    }), 503, 'none');
  };
})();
