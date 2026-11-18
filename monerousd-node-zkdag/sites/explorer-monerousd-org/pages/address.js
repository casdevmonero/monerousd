// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// address.js — /address/<address>
//
// HONEST BY SOURCE (user 2026-11-15: "Make our explorer honest … actually explain what our code does"). This page used to
// ask an indexer route (/v1/activity) for a per-address table of blocks, directions and amounts. No node serves that route,
// and none can: an address never reaches the chain. A MoneroUSD address is base58(tag ‖ 32-byte spend tag ‖ 1,184-byte
// ML-KEM-768 encapsulation key ‖ 4-byte Keccak-256 checksum) (monerousd-node-zkdag/src/address.rs). A sender seals each note
// to that key, and the chain stores only the note's commitment and ciphertext (src/mempool.rs, PqTx output notes), so
// nothing on chain names the address. A page that showed activity "for an address" would be asking a server which notes are
// whose, exactly the which-item question digital cash refuses. So this page reads nothing: it decodes what the address
// itself says and explains why the chain has nothing more.
import { escapeHtml } from '../lib/helpers.js';

const B58 = /^[1-9A-HJ-NP-Za-km-z]+$/;
// A well-formed address is block base58 (8-byte blocks → 11 characters) over 1,224 bytes: the network tag's 4-byte varint,
// the 32-byte spend tag, the 1,184-byte ML-KEM-768 key and the 4-byte checksum — exactly 1,683 characters (address.rs,
// `encode_addr_matches_wallet_ground_truth`). The checksum is not re-checked here; the page shows nothing that depends on it.
const ADDRESS_CHARS = 1683;

export async function renderAddress({ view }, addr) {
  const shape = (addr || '').length === ADDRESS_CHARS && B58.test(addr)
    ? 'A MoneroUSD address: a 32-byte spend tag and a 1,184-byte ML-KEM-768 key, with a Keccak-256 checksum.'
    : 'This is not the shape of a MoneroUSD address (one is 1,683 base58 characters: a network tag, a spend tag, an ML-KEM-768 key and a checksum).';
  view.innerHTML = `
    <section>
      <h2>Address</h2>
      <div class="detail-table">
        <table>
          <tbody>
            <tr><td class="label">Address</td><td class="mono break-all">${escapeHtml(addr)}</td></tr>
            <tr><td class="label">Shape</td><td>${escapeHtml(shape)}</td></tr>
          </tbody>
        </table>
      </div>

      <div class="privacy-note">
        <strong>Nothing on chain refers to this address.</strong> A payment to it is a note sealed to its ML-KEM-768 key:
        the chain stores the note's commitment and ciphertext, never the address. So there is no balance, no history and no
        list of payments to show, here or on any node. Only the holder of the address's keys can find its notes, by
        opening them in their own wallet.
      </div>
    </section>
  `;
}
