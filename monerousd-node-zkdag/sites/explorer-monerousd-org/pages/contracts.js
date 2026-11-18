// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// contracts.js — /contracts
// Dark Contract registry browser. Mirrors monerousd-explorer/views/contracts.ejs.
import { escapeHtml, shortAddr } from '../lib/helpers.js';

export async function renderContracts({ ds, view }) {
  let contracts = [];
  let errorMsg = null;

  try {
    // /v1/contracts is served by the user's OWN node (the sovereign server routes /v1 to the node backend). A clearnet
    // fetch to ion.monerousd.org leaked the user's IP to a third party (hole scanner 2026-10-03); a failure now surfaces
    // as the page's error instead of silently reading as "no contracts".
    const r = await fetch('/v1/contracts').then(r => r.json());
    if (r && Array.isArray(r)) contracts = r;
    else if (r && r.contracts) contracts = r.contracts;
    else if (r && r.items) contracts = r.items;
  } catch (e) {
    errorMsg = e && e.message || String(e);
  }

  view.innerHTML = `
    <section>
      <h2>Dark Contracts</h2>
      <p class="muted">Every deployed Dark Contract on the MoneroUSD chain. Click a row to inspect its ABI and call entrypoints from your wallet.</p>

      ${errorMsg ? `<div class="error-box"><strong>Error:</strong> ${escapeHtml(errorMsg)}</div>` : ''}

      ${(!errorMsg && contracts.length === 0) ? `
        <div class="empty">
          <p>No contracts deployed yet.</p>
          <p class="muted">Be the first &mdash; open the deploy helper in your wallet.</p>
        </div>
      ` : ''}

      ${contracts.length > 0 ? `
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Contract ID</th>
              <th>Deployer</th>
              <th>Created</th>
              <th>Code hash</th>
            </tr>
          </thead>
          <tbody>
            ${contracts.map(c => {
              const id = c.id || c.contractId || '';
              const name = c.verifiedName || c.name || (c.abi && c.abi.name) || '(unnamed)';
              const deployer = c.deployer || c.deployerStealth || '';
              const codeHash = c.codeHash || c.code_hash || '';
              const verified = !!c.verified;
              return `
                <tr>
                  <td>
                    <a href="#/contract/${encodeURIComponent(id)}">
                      <strong>${escapeHtml(name)}</strong>
                      ${verified ? `<span class="badge badge-verified" style="margin-left:6px;font-size:0.7rem">&#10003;</span>` : ''}
                    </a>
                  </td>
                  <td class="mono" data-copy="${escapeHtml(id)}" title="Click to copy">${escapeHtml(shortAddr(id))}</td>
                  <td class="mono muted" data-copy="${escapeHtml(deployer)}" title="Click to copy">${escapeHtml(shortAddr(deployer))}</td>
                  <td>${c.createdBlock || c.created_block ? `<a href="#/block/${c.createdBlock || c.created_block}">${(c.createdBlock || c.created_block).toLocaleString ? (c.createdBlock || c.created_block).toLocaleString() : c.createdBlock || c.created_block}</a>` : '—'}</td>
                  <td class="mono muted" data-copy="${escapeHtml(codeHash)}" title="Click to copy">${escapeHtml(shortAddr(codeHash))}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
      ` : ''}
    </section>
  `;
}
