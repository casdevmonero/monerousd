// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// pages/tx.js — /tx/<id>: what a MoneroUSD transaction is.
//
// HONEST BY SOURCE (user 2026-11-15: "Make our explorer honest … actually explain what our code does"). This page used to call
// a daemon route `get_transactions` that no MoneroUSD node serves, and decode the answer as another chain's transaction format:
// inputs and outputs, curve-based membership and range proofs, version numbers of that chain. None of it exists here. A
// MoneroUSD transaction (monerousd-node-zkdag/src/mempool.rs, `PqTx`) is:
//   id ............. blake3 of its bytes
//   blob ........... the confidential spend: one WHIR zero-knowledge proof plus its outputs
//   nullifiers ..... one per note it spends, Poseidon2(nk, cm) — refused if already in the spent set
//   pow_stamp ...... a fixed 8-byte anti-spam stamp
//   output notes ... 1,153 bytes each: a 32-byte commitment, a 1,088-byte ML-KEM-768 ciphertext, 32 encrypted amount bytes, a
//                    1-byte view tag
// and every block carries the same number of transaction slots, real ones and value-0 cover ones alike (src/cover.rs).
// No node serves a transaction's body by its id: asking a server for one payment by id tells it which payment you care about,
// the which-item question digital cash refuses. So this page fetches nothing; it shows the id and what any transaction holds.
import { escapeHtml } from '../lib/helpers.js';

export async function renderTx({ view }, hash) {
  if (!/^[0-9a-fA-F]{64}$/.test(hash || '')) {
    view.innerHTML = `<div class="error-box"><strong>Not a transaction id</strong>
      <p>A transaction id is 64 hex characters: the blake3 hash of the transaction's bytes.</p></div>`;
    return;
  }
  view.innerHTML = `
    <section>
      <h2>Transaction</h2>
      <div class="detail-table">
        <table>
          <tbody>
            <tr><td class="label">Id</td><td class="mono break-all">${escapeHtml(hash.toLowerCase())}</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="card">
      <div class="card-header"><h2>What every MoneroUSD transaction holds</h2></div>
      <dl class="kv-table">
        <dt>Id</dt>           <dd>The blake3 hash of its bytes.</dd>
        <dt>Proof</dt>        <dd>One WHIR zero-knowledge proof: each note it spends is in the note tree, each nullifier is that
                                  note's, inputs equal outputs plus fee, and every value fits in 64 bits. It reveals none of them.</dd>
        <dt>Nullifiers</dt>   <dd>One per note spent, <code>Poseidon2(nk, cm)</code>. Only the owner's key ties one to its note; a
                                  nullifier already in the spent set is refused.</dd>
        <dt>Notes</dt>        <dd>1,153 bytes each: a commitment, an ML-KEM-768 ciphertext sealed to the recipient, the encrypted
                                  amount and a one-byte tag that lets the recipient's wallet skip notes that are not theirs.</dd>
        <dt>Anti-spam stamp</dt><dd>A fixed 8-byte proof of work, the same width on every transaction.</dd>
      </dl>
    </section>

    <section class="card">
      <div class="card-header"><h2>Why there is nothing more to show</h2></div>
      <p style="margin:0;font-size:13px;color:var(--text-secondary);line-height:1.6">
        No sender, recipient or amount is in a transaction's bytes, and every transaction has the same shape. No node serves a
        transaction by its id either: asking a server for one payment would tell it which payment you care about.
        <a href="#/privacy">How privacy works →</a>
      </p>
    </section>
  `;
}
