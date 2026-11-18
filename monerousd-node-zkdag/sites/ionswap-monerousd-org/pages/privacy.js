// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// pages/privacy.js — what an analyst holding both public chains can and cannot link (2026-11-10). Words and bars
// only: it reads nothing and sends nothing.
//
// THE FIGURES ARE THE NODE'S OWN CENSUS (`monerousd-node-zkdag/src/swap_linkability.rs`, measured 2026-11-10): one
// simulated day at each volume; the analyst reads every deposit and every payout on both chains, knows every fee and
// every batch price, and names a deposit for each payout piece with amount × price, timing with budgets, address
// clustering and run sums; a piece counts as linked when ANY of them is right. A figure here changes only when that
// census is run again and reads differently.
import { esc } from '../lib/native.js';

const bar = (cls, label, value, pct) =>
  '<div class="m ' + cls + '"><span>' + esc(label) + '</span><b class="num">' + esc(value) + '</b><div class="track"><i data-w="' + pct + '%"></i></div></div>';

export default async function render(view /* , ctx */) {
  const root = document.createElement('section');
  root.className = 'ion page';
  root.innerHTML =
    '<div><div class="eyebrow">Measured, not promised</div><h1>What an analyst<br><em>can and cannot see.</em></h1>' +
    '<p class="lead">Moving from a public coin to another public coin is exactly what chain-analysis firms trace on other bridges: match the amount, at the price of the minute, inside a time window. We ran that analysis against our own bridge, with both chains fully visible to the analyst.</p></div>' +
    '<div class="two"><div class="card stack"><h2>Payout pieces the analyst links to the right deposit</h2><div class="meter">' +
    bar('bad', 'Paid at once to one address (Auto-OPSEC off)', '90 to 100 in 100', 96) +
    bar('good', 'Auto-OPSEC on · 100 users per day', 'about 2 in 100', 2.2) +
    bar('good', 'Auto-OPSEC on · 1,000 users per day', 'about 2 in 1,000', 0.7) +
    bar('good', 'Auto-OPSEC on · 10,000 users per day', 'about 2 in 10,000', 0.4) +
    '</div><div class="muted">One simulated day at each volume. The analyst knows every fee and every batch price and tries five methods on every payout piece; a piece counts as linked if any one of them names the right deposit.</div></div>' +
    '<div class="card stack"><h2>How Auto-OPSEC does it</h2><div class="steps">' +
    '<div><div><b>Standard pieces</b><span>What you receive is paid in a few standard sizes, the same sizes everyone is paid in. No payout carries your amount.</span></div></div>' +
    '<div><div><b>A fresh address for every piece</b><span>On a public chain each piece goes to an address of yours nobody has seen. Pieces never add up in public.</span></div></div>' +
    '<div><div><b>Each piece in its own batch</b><span>Pieces leave at different times, each beside other people\'s pieces of the same size.</span></div></div>' +
    '<div><div><b>No memo, no account</b><span>The request travels inside the private chain. Nothing on either public chain says where a payout came from.</span></div></div>' +
    '</div><div class="note">With Auto-OPSEC on, each piece leaves in its own batch, so the last one can arrive up to a day after the first. Auto-OPSEC can be switched off in your wallet; the wallet warns you first, and the payout then leaves in the next batch, where it can be matched.</div></div></div>';
  view.appendChild(root);
  requestAnimationFrame(() => root.querySelectorAll('.track i').forEach((i) => { i.style.width = i.dataset.w; }));
}
