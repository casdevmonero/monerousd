// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// pages/usernames.js — @names: look one up, see whether it is free and what it costs to claim (the chain's own price
// for the bytes every node keeps), claim it through the wallet, and browse the names claimed most recently.
//
// A @name is opt-in public: it points at a receive address its owner chose to publish. Paying a @name stays private
// (the payer's wallet asks the name's wallet for a one-time address). This page never lists which address a name
// points to; it says only whether the name is held.

import * as chain from '../lib/chain.js';
import { escapeHtml as esc } from '../lib/helpers.js';
import { connectPanel, toast } from './common.js';

const NAME_OK = /^[a-z0-9_.-]{1,32}$/;

export async function renderUsernames({ ds, view }, initial) {
  view.innerHTML = `
    <header class="hero rv">
      <span class="kick">@names</span>
      <h1>Your name on MoneroUSD. <span class="or">Paid to, privately.</span></h1>
      <p>A @name lets anyone pay you without copying an address. It is public by choice; the payments to it stay
        private — each payer’s wallet gets a fresh one-time address from yours.</p>
      <form class="name-search" id="name-form" autocomplete="off">
        <span class="at">@</span>
        <input id="name-input" maxlength="33" spellcheck="false" placeholder="yourname" aria-label="A name to look up" value="${esc(chain.canonName(initial || ''))}">
        <button class="btn btn-primary" type="submit">Look up</button>
      </form>
      <div id="name-result"></div>
    </header>
    <section class="section">
      <div class="steps">
        <div class="step rv d1"><b>01 · LOOK UP</b><p>Type a name. Your node answers whether anyone holds it — nobody else learns you asked.</p></div>
        <div class="step rv d2"><b>02 · CLAIM</b><p>Your wallet shows the price in dollars before you confirm. A name nobody holds is first come, first served.</p></div>
        <div class="step rv d3"><b>03 · GET PAID</b><p>Share @yourname. Every payment lands privately; nobody can list what you received.</p></div>
      </div>
    </section>
    <section class="section">
      <div class="section-head rv"><div><span class="kick">On the chain</span><h2>Recently claimed</h2>
        <p>Newest first, from your node’s copy of the directory.</p></div></div>
      <div id="names-recent"><div class="loading">Reading the chain’s directory…</div></div>
    </section>`;

  const form = view.querySelector('#name-form');
  const input = view.querySelector('#name-input');
  const out = view.querySelector('#name-result');
  const recent = view.querySelector('#names-recent');

  const reachable = await ds.nodeReachable();
  if (!reachable) {
    recent.innerHTML = connectPanel();
    form.addEventListener('submit', (e) => { e.preventDefault(); out.innerHTML = connectPanel(); });
    return;
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const name = chain.canonName(input.value);
    if (location.hash !== '#/names/' + encodeURIComponent(name)) history.replaceState(null, '', '#/names/' + encodeURIComponent(name));
    lookup(ds, out, name);
  });
  if (initial) lookup(ds, out, chain.canonName(initial));

  try {
    const r = await chain.recentNames(36);
    recent.innerHTML = r.items.length ? `<div class="listing-grid">${r.items.map((n, i) => `
      <a class="listing rv d${(i % 4) + 1}" href="#/names/${encodeURIComponent(n.name)}">
        <div class="name-handle">@${esc(n.name)}</div>
        <div class="row"><span class="len">${n.name.length} char${n.name.length === 1 ? '' : 's'}</span>
          <span class="muted" style="font-size:13px">${n.handedOver ? 'changed hands' : 'claimed'}</span></div>
      </a>`).join('')}</div>` : `<div class="empty-state"><div class="empty-state-title">No names claimed yet</div><p class="muted">Be the first: look one up above.</p></div>`;
  } catch (e) {
    recent.innerHTML = `<div class="error-box"><strong>Your node did not serve its directory</strong>${esc(e.message)}</div>`;
  }
}

async function lookup(ds, out, name) {
  if (!NAME_OK.exec(name)) {
    out.innerHTML = `<div class="name-result taken"><div><div class="name-handle">@${esc(name || '…')}</div>
      <div class="name-state">A name is 1 to 32 characters: letters a–z, digits, and <code>_ . -</code></div></div></div>`;
    return;
  }
  out.innerHTML = `<div class="name-result"><div class="name-handle">@${esc(name)}</div><div class="loading" style="padding:8px 0">Asking your node…</div></div>`;
  let holder;
  try {
    holder = await chain.resolveName(name);
  } catch (e) {
    out.innerHTML = `<div class="error-box"><strong>Your node did not answer</strong>${esc(e.message)}</div>`;
    return;
  }
  if (holder) {
    out.innerHTML = `<div class="name-result taken">
      <div><div class="name-handle">@${esc(name)}</div>
        <div class="name-state"><span class="badge badge-warning">Taken</span> Someone holds this name. You can pay it from your wallet.</div></div>
      <div class="name-actions"><a class="btn btn-ghost btn-sm" href="#/names">Try another name</a></div></div>`;
    return;
  }
  const inWallet = !!(window.monerousd && typeof window.monerousd.dirRegister === 'function');
  out.innerHTML = `<div class="name-result free">
    <div><div class="name-handle">@${esc(name)}</div>
      <div class="name-state"><span class="badge badge-success">Available</span> Nobody holds it. First to claim it gets it.</div></div>
    <div class="name-price"><b>About $10</b><span>the wallet’s yearly name fee plus a few cents of chain fee for the bytes every node keeps — shown exactly, in dollars, before you confirm</span></div>
    <div class="name-actions">
      ${inWallet ? '<button class="btn btn-primary" id="claim-btn">Claim @' + esc(name) + '</button>'
        // outside the wallet the button hands THIS page to the wallet's own browser (`monerousd://browse`, web3_bridge::
        // link_browse), where the same button claims in one tap with its cost shown first: the person is never sent off
        : '<a class="btn btn-primary" href="monerousd://browse?url=' + encodeURIComponent(location.href) + '">Claim @' + esc(name) + ' with your wallet</a>'
          + '<span class="muted">No wallet yet? <a href="https://monerousd.org/testnet">Get the MoneroUSD wallet</a>.</span>'}
    </div></div>`;
  const btn = out.querySelector('#claim-btn');
  if (btn) btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = 'Confirm in your wallet…';
    try {
      const r = await window.monerousd.dirRegister({ key: name });
      if (r && r.ok && r.result === 'PENDING') {
        btn.textContent = 'Sent — waiting for a block';
        toast('@' + name + ' is on its way to the chain. It is yours once a block carries it.');
        waitForName(name, out, btn);
      } else if (r && r.result === 'UPDATED') {
        btn.textContent = '@' + name + ' is already yours';
      } else {
        btn.disabled = false; btn.textContent = 'Claim @' + name;
        toast(r && r.result === 'TAKEN' ? 'Someone claimed @' + name + ' first. You were not charged.' : 'The wallet did not send it.');
      }
    } catch (e) {
      btn.disabled = false; btn.textContent = 'Claim @' + name;
      toast(String(e.message || e).replace(/^USER_DECLINED: /, ''));
    }
  });
}

// Confirmation poll: one resolve on this machine's node every 900 ms until the chain holds the name.
function waitForName(name, out, btn) {
  let ticks = 0;
  const poll = setInterval(async () => {
    if (!out.isConnected || ++ticks > 400) { clearInterval(poll); return; }
    if (await chain.resolveName(name).catch(() => null)) {
      clearInterval(poll);
      btn.textContent = '@' + name + ' is yours';
      btn.classList.remove('btn-primary');
      toast('@' + name + ' is on the chain.');
    }
  }, 900);
}
