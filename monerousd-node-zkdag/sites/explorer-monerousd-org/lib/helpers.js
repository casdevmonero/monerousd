// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// helpers.js — formatting + badge helpers ported from monerousd-explorer
// app.js (the legacy server-side EJS render). Kept here so every page
// gets identical formatting whether it queries daemon RPC directly or
// the federated indexer.

// 8-decimal atomic units throughout MoneroUSD (see CLAUDE.md atomic-units rule).
const ATOMIC = 1e8;

// The gold check belongs to the chain's two native assets only. They never come from the directory, so a launched
// token whose symbol matches one in any letter case is a copy, and is shown with a warning.
export const VERIFIED_TOKENS = Object.freeze({
  'USDm': { name: 'MoneroUSD', issuer: 'MoneroUSD Protocol', org: 'monerousd-protocol', verified: true },
  'SAT':  { name: 'Satoshi',   issuer: 'MoneroUSD Protocol', org: 'monerousd-protocol', verified: true },
});

export function isVerified(symbol) {
  return !!VERIFIED_TOKENS[symbol];
}

// For a token from the directory: does its symbol copy a native asset's?
export function isCloneAttempt(symbol) {
  const upper = String(symbol || '').toUpperCase();
  return Object.keys(VERIFIED_TOKENS).some(k => k.toUpperCase() === upper);
}

export function badgeHtml(symbol) {
  if (!symbol) return '';
  if (isVerified(symbol)) {
    const v = VERIFIED_TOKENS[symbol];
    return `<span class="badge badge-verified" title="${escapeAttr(v.name + ' — ' + v.issuer)}">&#10003; ${escapeHtml(symbol)}</span>`;
  }
  if (isCloneAttempt(symbol)) {
    return `<span class="badge badge-clone-warning" title="Unofficial token using a verified name">&#9888; ${escapeHtml(symbol)}</span>`;
  }
  return `<span class="badge">${escapeHtml(symbol)}</span>`;
}

// ── numeric / temporal formatting ──────────────────────────────────

export function formatAmount(atomic) {
  if (atomic == null) return '—';
  const big = BigInt(String(atomic));
  const whole = big / BigInt(ATOMIC);
  const frac  = (big % BigInt(ATOMIC)).toString().padStart(8, '0').replace(/0+$/, '');
  return whole.toLocaleString('en-US') + (frac ? '.' + frac : '');
}

export function formatDifficulty(d) {
  if (!d) return 'N/A';
  const n = Number(d);
  if (n >= 1e9) return (n / 1e9).toFixed(2) + ' G';
  if (n >= 1e6) return (n / 1e6).toFixed(2) + ' M';
  if (n >= 1e3) return (n / 1e3).toFixed(2) + ' K';
  return n.toLocaleString();
}

export function formatHashrate(hps) {
  if (!hps || !isFinite(hps)) return 'N/A';
  const n = Number(hps);
  if (n >= 1e12) return (n / 1e12).toFixed(2) + ' TH/s';
  if (n >= 1e9)  return (n / 1e9).toFixed(2)  + ' GH/s';
  if (n >= 1e6)  return (n / 1e6).toFixed(2)  + ' MH/s';
  if (n >= 1e3)  return (n / 1e3).toFixed(2)  + ' KH/s';
  return n.toFixed(2) + ' H/s';
}

export function timeSince(unixSec) {
  if (!unixSec) return '—';
  const diff = Math.floor(Date.now() / 1000) - Number(unixSec);
  if (diff < 0) return 'just now';
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

export function shortAddr(s, lead = 12, tail = 6) {
  if (!s || typeof s !== 'string') return '—';
  if (s.length <= lead + tail + 3) return s;
  return s.slice(0, lead) + '…' + s.slice(-tail);
}

// ── tx classification (ported from legacy detectTxBadge) ───────────
//
// Carrier txs in MoneroUSD encode bridge / conversion / transfer
// operations as `ion://op/v1?code=…&payload=…` in tx_extra. The
// detector reads tx.extra (when decoded) and surfaces the badge
// type used in the block + tx pages.

export function detectTxBadge(tx) {
  if (!tx || !tx.extra) return null;
  const extra = String(tx.extra || '');
  const m = extra.match(/ion:\/\/op\/v1\?code=([A-Z_]+)/);
  if (!m) return null;
  const code = m[1];
  // Asset detection
  const assetMatch = extra.match(/asset=([A-Za-z0-9_-]+)/);
  const asset = assetMatch ? assetMatch[1] : null;
  switch (code) {
    case 'BRIDGE_WRAP':   return { type: 'bridge-wrap',   asset, label: 'Wrap' };
    case 'BRIDGE_UNWRAP': return { type: 'bridge-unwrap', asset, label: 'Unwrap' };
    case 'BRIDGE_MINT':   return { type: 'bridge-wrap',   asset, label: 'Mint' };
    case 'BRIDGE_BURN':   return { type: 'bridge-unwrap', asset, label: 'Burn' };
    case 'TOKEN_TRANSFER':return { type: 'asset-transfer', asset, label: 'Transfer' };
    case 'TOKEN_CREATE':  return { type: 'asset-transfer', asset, label: 'Create' };
    case 'SWAP_FILL':     return { type: 'conversion',    asset, label: 'Swap' };
    case 'LP_MINT':       return { type: 'conversion',    asset, label: 'LP Mint' };
    case 'LP_BURN':       return { type: 'conversion',    asset, label: 'LP Burn' };
    case 'DC_DEPLOY':     return { type: 'asset-transfer', asset: null, label: 'Deploy DC' };
    case 'DC_CALL_DIRECT':
    case 'DC_CALL_COMMIT':
    case 'DC_CALL_REVEAL': return { type: 'asset-transfer', asset: null, label: code.replace('DC_CALL_', 'DC ') };
    default: return { type: 'asset-transfer', asset, label: code };
  }
}

export function getTxTypeName(tx) {
  if (!tx) return 'TRANSFER';
  const t = tx.tx_type ?? tx.type ?? 0;
  const map = ['TRANSFER', 'OFFSHORE', 'ONSHORE', 'OFFSHORE_TRANSFER', 'XUSD_TO_XASSET', 'XASSET_TO_XUSD', 'XASSET_TRANSFER'];
  return map[t] || 'TRANSFER';
}

// ── HTML escapers (no external deps) ───────────────────────────────

export function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function escapeAttr(s) {
  return escapeHtml(s);
}

// ─── Gold verified check ──────────────────────────────────────────
//
// Reusable inline SVG. The shape is a 12-pointed scalloped star
// (Twitter/X gold-check silhouette), filled with a metallic-gold
// radial gradient (highlights + deep gold body + warm shadow), then
// stroked at the edges for definition. The check glyph is solid
// white with rounded joins.
//
// Each call generates a UNIQUE gradient `id` (incrementing counter)
// so multiple instances on one page don't share the gradient
// reference — important because Safari ignores `defs` collisions
// silently and the second instance would render unfilled.
//
// Usage:
//   `${goldCheckHTML()}`              // 14 px
//   `${goldCheckHTML('lg')}`          // 18 px
//   `${goldCheckHTML('xl')}`          // 22 px

let _gcid = 0;
export function goldCheckHTML(size = '', title = 'Verified') {
  const id  = ++_gcid;
  const cls = 'gold-check' + (size ? ' gold-check--' + size : '');
  return `<span class="${cls}" role="img" aria-label="${escapeAttr(title)}" title="${escapeAttr(title)}">` +
    `<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">` +
      `<defs>` +
        // Metallic gold burst — highlight at upper-left, deep gold body,
        // darker rim. Mimics the Twitter Blue gold check colors.
        `<radialGradient id="gc-burst-${id}" cx="35%" cy="32%" r="78%">` +
          `<stop offset="0%"  stop-color="#FFF1B5"/>` +
          `<stop offset="38%" stop-color="#FFD24A"/>` +
          `<stop offset="74%" stop-color="#E8A11A"/>` +
          `<stop offset="100%" stop-color="#8E5A0A"/>` +
        `</radialGradient>` +
        // Subtle inner shine — overlay to give the surface depth.
        `<linearGradient id="gc-shine-${id}" x1="20%" y1="0%" x2="80%" y2="100%">` +
          `<stop offset="0%"  stop-color="#FFF7C8" stop-opacity="0.55"/>` +
          `<stop offset="35%" stop-color="#FFF7C8" stop-opacity="0"/>` +
          `<stop offset="100%" stop-color="#000000" stop-opacity="0"/>` +
        `</linearGradient>` +
      `</defs>` +
      // 12-pointed scalloped star — same shape Twitter/X uses for
      // its premium-gold tick. Constructed as a series of inner +
      // outer scallops around a 32 × 32 box centred at (16,16).
      `<path d="M16 1.6 18.9 4.7 23.1 3.9 24.6 7.9 28.5 9.9 27.8 14.2 30.4 17.5 28.0 21.0 28.7 25.2 24.5 26.1 22.6 29.8 18.6 28.2 16 31.4 13.4 28.2 9.4 29.8 7.5 26.1 3.3 25.2 4.0 21.0 1.6 17.5 4.2 14.2 3.5 9.9 7.5 7.9 9.4 3.9 13.4 4.7 16 1.6Z" ` +
            `fill="url(#gc-burst-${id})" stroke="#7A4C0E" stroke-width="0.6" stroke-linejoin="round"/>` +
      // Inner shine overlay.
      `<path d="M16 1.6 18.9 4.7 23.1 3.9 24.6 7.9 28.5 9.9 27.8 14.2 30.4 17.5 28.0 21.0 28.7 25.2 24.5 26.1 22.6 29.8 18.6 28.2 16 31.4 13.4 28.2 9.4 29.8 7.5 26.1 3.3 25.2 4.0 21.0 1.6 17.5 4.2 14.2 3.5 9.9 7.5 7.9 9.4 3.9 13.4 4.7 16 1.6Z" ` +
            `fill="url(#gc-shine-${id})"/>` +
      // Check glyph — solid white, rounded.
      `<path d="M10.4 16.6 14.2 20.3 21.8 12.6" ` +
            `fill="none" stroke="#FFFFFF" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>` +
    `</svg>` +
    `<span class="sr-only">${escapeAttr(title)}</span>` +
  `</span>`;
}

// THE HTML-SINK CLASS (2026-10-05): a REAL DOM sanitizer for the sinks that take helper-built markup — allowlisted tags,
// no on*/srcdoc/javascript:/non-image data: attributes. Values that can carry outside text are escaped at their source
// (escapeHtml); this is the second layer at the sink.
const SANITIZE_SAFE_TAGS = new Set(['div', 'span', 'b', 'i', 'em', 'strong', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'pre', 'code', 'button', 'a', 'img', 'small', 'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'table', 'thead', 'tbody', 'tr', 'td', 'th', 'label', 'input', 'select', 'option', 'section', 'article', 'header', 'footer', 'nav', 'hr', 'kbd', 'details', 'summary', 'time', 'svg', 'path', 'circle', 'ellipse', 'rect', 'g', 'defs', 'lineargradient', 'radialgradient', 'stop', 'text', 'title', 'use', 'polygon', 'polyline', 'line', 'clippath', 'mask']);
export function sanitizeHtml(markup) {
  const doc = new DOMParser().parseFromString('<body>' + String(markup == null ? '' : markup) + '</body>', 'text/html');
  const walk = (node) => {
    for (const el of Array.from(node.children)) {
      if (!SANITIZE_SAFE_TAGS.has(el.tagName.toLowerCase())) { el.remove(); continue; }
      for (const a of Array.from(el.attributes)) {
        const n = a.name.toLowerCase(), v = String(a.value || '').trim().toLowerCase().replace(/\s+/g, '');
        const url = n === 'href' || n === 'src' || n === 'action' || n === 'xlink:href' || n === 'formaction';
        if (n.startsWith('on') || n === 'srcdoc' || (url && (v.startsWith('javascript:') || v.startsWith('vbscript:') || (v.startsWith('data:') && !v.startsWith('data:image/'))))) el.removeAttribute(a.name);
      }
      walk(el);
    }
  };
  walk(doc.body);
  return doc.body.innerHTML;
}
