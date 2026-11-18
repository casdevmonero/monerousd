// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// pages/common.js — the pieces every explorer page shares: the page head, the "connect your node" panel, logo boxes
// and the number formats (8-decimal atomic units everywhere).

import { escapeHtml as esc } from '../lib/helpers.js';
import { initials } from '../lib/registries.js';

export function pageHead(kick, title, lead) {
  return `<header class="hero rv"><span class="kick">${esc(kick)}</span><h1>${esc(title)}</h1>${lead ? `<p>${esc(lead)}</p>` : ''}</header>`;
}

export function connectPanel() {
  return `<section class="connect">
    <div><span class="kick">No node connected</span>
      <h2>This page reads the chain from <span class="or">your own node</span>.</h2>
      <p>There is no MoneroUSD server to ask, and a node answers only its own wallet and the pages it serves itself.</p></div>
    <ol>
      <li><span><strong>In the wallet:</strong> open Apps → Explorer.</span></li>
      <li><span><strong>From your node:</strong> open <code>http://127.0.0.1:27752/explorer-monerousd-org/</code>.</span></li>
      <li><span><strong>New here?</strong> <a href="https://monerousd.org/testnet">Join the testnet</a>.</span></li>
    </ol></section>`;
}

// A logo image that turns into the entity's initials if it fails to load (the delegated handler in app.js).
export function logoBox(url, name, round = false) {
  const ini = initials(name);
  return `<div class="entity-logo${round ? ' round' : ''}">${url ? `<img src="${esc(url)}" alt="" data-initials="${esc(ini)}">` : `<span>${esc(ini)}</span>`}</div>`;
}

// A pool's clearing price, `price_e12` = USDm per whole token × 10^12.
export function fmtPrice(e12) {
  const n = Number(e12) / 1e12;
  if (!isFinite(n) || n <= 0) return '—';
  if (n >= 1000) return n.toLocaleString('en-US', { maximumFractionDigits: 0 });
  if (n >= 1) return n.toLocaleString('en-US', { maximumFractionDigits: 4 });
  return n.toPrecision(4);
}

// An atomic amount (8 decimals) as whole units, compact.
export function fmtSupply(atomic) {
  let big;
  try { big = BigInt(String(atomic)); } catch (_) { return '—'; }
  const whole = Number(big / 100000000n);
  if (whole >= 1e9) return (whole / 1e9).toFixed(2) + 'B';
  if (whole >= 1e6) return (whole / 1e6).toFixed(2) + 'M';
  if (whole >= 1e3) return (whole / 1e3).toFixed(1) + 'K';
  return whole.toLocaleString('en-US');
}

export function fmtUsdm(atomic) {
  let big;
  try { big = BigInt(String(atomic)); } catch (_) { return '—'; }
  const whole = big / 100000000n, frac = (big % 100000000n).toString().padStart(8, '0').replace(/0+$/, '');
  return whole.toLocaleString('en-US') + (frac ? '.' + frac.slice(0, 4) : '');
}

// A short message at the bottom of the screen; its CSS animation fades it out and it removes itself when that ends.
export function toast(msg) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  t.addEventListener('animationend', (e) => { if (e.animationName === 'toastlife') t.remove(); });
  document.body.appendChild(t);
}
