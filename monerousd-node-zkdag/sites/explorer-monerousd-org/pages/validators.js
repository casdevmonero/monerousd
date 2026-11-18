// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// pages/validators.js — what securing the bridge's custody costs, from the node's own public figures (`/takeover_cost`):
// the SAT bonded to custody, the security the bottom two-thirds of it give, and the SAT a newcomer would have to bond to
// hold more than two-thirds alone. Borrowed from THORChain's effective security bond. No validator is named here.

import { takeoverCost } from '../lib/data-source.js';
import { escapeHtml as esc } from '../lib/helpers.js';
import { pageHead, connectPanel, fmtSupply } from './common.js';

export async function renderValidators({ ds, view }) {
  view.innerHTML = pageHead('Validators', 'What it costs to attack custody',
    'Validators bond SAT to sign for the bridge’s native-coin vaults, in committees of a fixed size. A validator that signs a theft loses its bond, and the bond repays the people it stole from.') + `
    <section class="stat-grid" id="val-stats">
      ${tile('total', 'SAT bonded to custody', 'every bonded validator')}
      ${tile('eff', 'Effective security', 'the bottom two-thirds of the bond')}
      ${tile('take', 'Cost to take over', 'SAT one newcomer must bond to hold > 2/3')}
    </section>
    <section class="card rv">
      <div class="card-header"><h2>How custody is protected</h2></div>
      <ul class="privacy-list">
        <li>Bonds are SAT, chosen by the wallet’s owner. A bond is released only after its custody key is dead.</li>
        <li>Custody keys are threshold post-quantum keys held by fixed-size committees; more nodes bring more committees, never bigger ones.</li>
        <li>Every coin that leaves a vault on its home chain (Bitcoin, Monero and the rest) has its entry on MoneroUSD, checked by every custodian on every poll.</li>
        <li>Re-keying, rotation and network fees are paid from the bonders’ own income — never from a pool or a user’s note.</li>
      </ul>
    </section>`;

  if (!(await ds.nodeReachable())) { view.querySelector('#val-stats').outerHTML = connectPanel(); return; }
  const paint = (t) => {
    const set = (k, v) => { const el = view.querySelector('#v-' + k); if (el) el.textContent = v == null ? '—' : fmtSupply(v) + ' SAT'; };
    set('total', t && t.custody_total_sat);
    set('eff', t && t.effective_security_sat);
    set('take', t && t.takeover_cost_sat);
    const sub = view.querySelector('#v-total-sub');
    if (sub && t && Number(t.custody_total_sat) === 0) sub.textContent = 'no custody bonded on the testnet yet';
  };
  paint(await takeoverCost());
  const timer = setInterval(async () => {
    if (!view.querySelector('#val-stats')) { clearInterval(timer); return; }
    paint(await takeoverCost());
  }, 30_000);
}

function tile(k, label, sub) {
  return `<div class="stat-tile rv"><div class="stat-tile-label">${esc(label)}</div><div class="stat-tile-value" id="v-${k}">—</div><div class="stat-tile-sub" id="v-${k}-sub">${esc(sub)}</div></div>`;
}
