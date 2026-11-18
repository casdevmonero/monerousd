// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Business Source License 1.1; see the LICENSE file in this directory (Apache-2.0 from 2029-12-01).

// frontend/lib/wallet-bridge.js
//
// NODE-FIRST WALLET BRIDGE (Pillar C, [[project_clearnet_backend_is_the_chain]]).
//
// When this app is framed inside the MoneroUSD desktop/mobile wallet, the wallet
// can't script-inject a foreign (clearnet) origin — so it announces itself over
// `postMessage` with `monerousd:hello`. On that handshake this module:
//
//   1. Installs `window.monerousd` — a postMessage-backed provider (connect /
//      getAddress / getBalance / transfer / nodeRpc), the exact surface the app's
//      provider-client.js already consumes.
//   2. Wraps `fetch` so EVERY backend call the app makes (`/api/*`, `/v1/*`,
//      `/rpc*` — whether via apiFetch or a bare fetch client) is routed through the
//      wallet to the user's OWN NODE. The CLEARNET app's backend therefore IS the
//      chain — zero VPS, identical to the sovereign build. The VPS is left serving
//      only the domain + static bytes.
//
// Outside the wallet (plain browser, or the sovereign same-origin build) NO hello
// ever arrives, `fetch` is untouched, and this module is completely inert.
(function () {
  'use strict';
  if (window.__MONEROUSD_WALLET_BRIDGE_INSTALLED__) return;
  window.__MONEROUSD_WALLET_BRIDGE_INSTALLED__ = true;

  var seq = 0;
  var pending = Object.create(null);
  var bridged = false;
  var parentOrigin = '*';

  // One RPC to the wallet: post `monerousd:rpc`, resolve on the matching `monerousd:res`.
  // `waitMs`: how long the answer may take. A read answers in moments; a call the user confirms in the wallet's own
  // sheet waits for the user, so its caller gives it minutes.
  function call(method, params, waitMs) {
    return new Promise(function (resolve, reject) {
      var id = 'wb' + (++seq);
      pending[id] = { resolve: resolve, reject: reject };
      try {
        window.parent.postMessage({ type: 'monerousd:rpc', id: id, method: method, params: params || {} }, parentOrigin);
      } catch (e) { delete pending[id]; reject(e); return; }
      setTimeout(function () {
        if (pending[id]) { var p = pending[id]; delete pending[id]; p.reject(new Error('wallet bridge timeout: ' + method)); }
      }, waitMs > 0 ? waitMs : 15000);
    });
  }

  // The provider surface provider-client.js expects. Every method rides the wallet → node.
  function installProvider() {
    if (window.monerousd && window.monerousd.__walletBridge) return;
    window.monerousd = {
      __walletBridge: true,
      isMoneroUSD: true,
      connect: function () { return call('connect'); },
      getAddress: function () { return call('getAddress').then(function (r) { return (r && r.address) ? r.address : r; }); },
      listAddresses: function () { return call('listAddresses'); },
      getNetwork: function () { return call('getNetwork'); },
      getHeight: function () { return call('getHeight'); },
      getBalance: function (p) { return call('getBalance', p); },
      transfer: function (p) { return call('transfer', p); },
      nodeRpc: function (path, body) { return call('nodeRpc', { path: path, body: body }); },
      request: function (path, body) { return call('nodeRpc', { path: path, body: body }); },
      // The wallet renders a QR for public data (a deposit address) — no third-party script is loaded to draw one.
      qrSvg: function (data) { return call('qrSvg', { data: String(data || '') }); },
      // Any other method this wallet answers (the wallet refuses one it does not know): how an app asks for what a
      // newer wallet added without this file naming each method.
      rpc: function (method, params, waitMs) { return call(String(method || ''), params || {}, waitMs); },
    };
  }

  // Is `url` a backend path we should route to the node? Only the app's own backend
  // family (same-origin, or a *.monerousd.org sibling like ion-testnet) — never a
  // third-party origin. Returns the node-relative path (network prefix stripped,
  // since the wallet's node already IS the selected network), or null to pass through.
  // On a SOVEREIGN origin (loopback / .onion) the app is already same-origin to the node — a plain fetch
  // hits /api directly, so we must NOT add a bridge hop. The bridge's fetch-routing is for CLEARNET only.
  function _isSovereignOrigin() {
    try {
      var h = window.location.hostname;
      return h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === '[::1]' || /\.onion$/.test(h);
    } catch (e) { return false; }
  }
  function nodePathOf(url) {
    if (_isSovereignOrigin()) return null;
    try {
      var u = new URL(url, window.location.href);
      var sameOrigin = u.origin === window.location.origin;
      var monerousdSibling = /(^|\.)monerousd\.org$/.test(u.hostname);
      if (!sameOrigin && !monerousdSibling) return null;
      if (!/^\/(testnet\/|mainnet\/)?(api|v1|rpc)(\/|$|\?)/.test(u.pathname)) return null;
      var path = (u.pathname + u.search).replace(/^\/(testnet|mainnet)(?=\/)/, '');
      return path;
    } catch (e) { return null; }
  }

  // Wrap fetch so backend calls ride the bridge → node when framed. Real fetch otherwise.
  var realFetch = window.fetch ? window.fetch.bind(window) : null;
  if (realFetch) {
    window.fetch = function (input, init) {
      if (bridged) {
        var url = (typeof input === 'string') ? input : (input && input.url);
        var path = url ? nodePathOf(url) : null;
        if (path) {
          var method = (init && init.method) || (typeof input !== 'string' && input && input.method) || 'GET';
          var rawBody = (init && init.body != null) ? init.body : null;
          var body = (method !== 'GET' && method !== 'HEAD' && rawBody != null) ? (typeof rawBody === 'string' ? rawBody : String(rawBody)) : '';
          return call('nodeRpc', { path: path, body: body }).then(function (data) {
            return new Response(JSON.stringify(data), { status: 200, statusText: 'OK', headers: { 'Content-Type': 'application/json' } });
          }).catch(function (e) {
            return new Response(JSON.stringify({ error: String((e && e.message) || e) }), { status: 502, statusText: 'Bad Gateway', headers: { 'Content-Type': 'application/json' } });
          });
        }
      }
      return realFetch(input, init);
    };
  }

  // Handshake + RPC replies from the wallet.
  window.addEventListener('message', function (ev) {
    var d = ev.data;
    if (!d) return;
    // Only the window that frames this app is the wallet: a hello or an answer from any other window is not one.
    if (ev.source !== window.parent) return;
    if (d.type === 'monerousd:hello') {
      bridged = true;
      parentOrigin = (ev.origin && ev.origin !== 'null') ? ev.origin : '*';
      installProvider();
      try { window.dispatchEvent(new Event('monerousd#initialized')); } catch (e) { void e; }
      return;
    }
    if (d.type === 'monerousd:res' && d.id && pending[d.id]) {
      var p = pending[d.id]; delete pending[d.id];
      if (d.ok) p.resolve(d.result); else p.reject(new Error(d.error || 'wallet bridge error'));
    }
  });
})();
