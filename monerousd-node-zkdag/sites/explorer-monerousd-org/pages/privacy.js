// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.
// pages/privacy.js — the privacy primer: what the chain conceals and what it publishes.
//
// HONEST BY SOURCE (user 2026-11-15: "the explorer privacy primer is incorrect. it list old/unused technology. Make our
// explorer honest … actually explain what our code does"). The previous page described another chain's cryptography, public
// AMM reserves and swap volumes, a public reserve counter and custody on coins we do not bridge; none of it is in MoneroUSD's
// code. Every line below names the mechanism the node and the prover actually run; the source file each lives in:
//   block header and body ........ monerousd-node-zkdag/src/block.rs (BlockHeader, Block)
//   a transaction and its notes .. src/mempool.rs (PqTx: blob, nullifiers, pow_stamp, output notes of 1153 bytes)
//   constant block shape ......... src/cover.rs (BLOCK_FIXED_TX_COUNT, BLOCK_FIXED_NOTE_COUNT = 256)
//   the spend's statement ........ vendor/Plonky3/usdm-decider/src/whir_rec_block.rs (frontier membership, nf = P(nk, cm),
//                                  SpendConservationGate with a 64-bit range per value)
//   finding your own notes ....... src/oli.rs (Oblivious Locator Index, LWE PIR) and the wallet's oli_client.rs
//   transport .................... src/arti_transport.rs (Tor v3 onion services, fixed-size cells)
//   the DeFi layer ............... src/defi_batch.rs (sealed orders, one clearing tick per batch)
//   the reserve .................. vendor/Plonky3/usdm-decider/src/confidential_solvency.rs (committed totals, ZK solvency)
//   the bridge ................... src/bridge.rs (bonded threshold custody, ML-DSA-65 mint attestations)
//   usernames .................... src/directory.rs (block-carried, ML-DSA-signed sign-ups)
// A static page: nothing here reads chain state, so it can never show a number the chain does not publish.

export async function renderPrivacy(ctx) {
  const { view } = ctx;
  view.innerHTML = `
    <header class="hero" style="padding:30px 32px">
      <span class="hero-eyebrow">Privacy primer</span>
      <h1 style="font-size:1.7rem">What MoneroUSD conceals — and what it publishes</h1>
      <p>MoneroUSD is post-quantum digital cash on a block-DAG. A payment is a zero-knowledge proof over hash-based
        commitments: there are no decoys, no elliptic curves and no public amounts on the chain. The cryptography is
        ML-KEM-768 (sealing notes to their owner), ML-DSA-65 (signatures), Poseidon2 and blake3 (commitments and
        hashes) and WHIR (the zero-knowledge proofs). Green is <strong>concealed</strong> by that cryptography; blue is
        <strong>public</strong> by design.</p>
    </header>

    <section class="card">
      <div class="card-header"><h2>By payment</h2></div>
      <div class="privacy-grid">
        <div class="privacy-col">
          <h3><span class="privacy-pill concealed">concealed</span></h3>
          <ul class="privacy-list">
            <li><strong>Sender</strong> — a spend proves, in zero knowledge, that the note it spends is a leaf of the
              chain's note tree: a Poseidon2 Merkle path to the public frontier root, checked inside the proof. It never
              says which leaf. The anonymity set is every note ever recorded, cover notes included, not a handful of
              chosen decoys.</li>
            <li><strong>Recipient</strong> — each output note is sealed to its recipient with ML-KEM-768. The chain
              holds a 32-byte note commitment and the 1,088-byte ciphertext; no address ever appears on chain.</li>
            <li><strong>Amount</strong> — encrypted inside the note, and bound by a Poseidon2 commitment. The proof
              checks that inputs equal outputs plus fee and that every value fits in 64 bits, without revealing any of
              them.</li>
            <li><strong>Which note was spent</strong> — a spend publishes its nullifier, <code>Poseidon2(nk, cm)</code>,
              computed from the owner's nullifier key. Nobody without that key can tie a nullifier to its note. A second
              spend of one note is refused because its nullifier is already in the spent set, an indexed Merkle tree whose
              root every block header commits.</li>
            <li><strong>How many payments a block carried</strong> — a node pads every block it produces to the same
              number of transactions and records exactly 256 notes. Real ones and value-0 cover ones are byte-for-byte
              indistinguishable, so the note tree grows by the same 256 every block, busy or idle. (Consensus caps these
              counts but never demands the cover, so a missing cover item can never stop the chain.)</li>
            <li><strong>Where you are</strong> — nodes talk only over Tor v3 onion services, in fixed-size cells. No IP
              address is on the wire.</li>
          </ul>
        </div>
        <div class="privacy-col">
          <h3><span class="privacy-pill public">public</span></h3>
          <ul class="privacy-list">
            <li><strong>Block headers</strong> — DAG parents, timestamp, the proof-of-useful-work nonce and work, and the
              roots the block commits: its transactions, the note tree after it and the spent set.</li>
            <li><strong>Each transaction's bytes</strong> — its id, its proof, its nullifiers, its notes' commitments and
              ciphertexts, and a fixed 8-byte anti-spam stamp. They are opaque: none of them names a sender, a recipient or
              an amount, and every transaction has the same shape.</li>
            <li><strong>The proofs</strong> — every spend proof is a WHIR proof any node verifies. They are hash-based,
              with no trusted setup.</li>
          </ul>
        </div>
      </div>
    </section>

    <section class="card">
      <div class="card-header"><h2>Across the ecosystem</h2></div>
      <div class="privacy-grid">
        <div class="privacy-col">
          <h3><span class="privacy-pill concealed">concealed</span></h3>
          <ul class="privacy-list">
            <li><strong>Finding your own payments</strong> — a wallet restores through the Oblivious Locator Index.
              Every block's index holds a constant 256 entries, and the wallet looks its entries up by lattice
              (LWE) private information retrieval in fixed-size batches padded with dummies. The node answering learns
              neither which entry was asked for nor how many were real. The wallet checks every match itself by
              opening the note.</li>
            <li><strong>Trades</strong> — a DeFi order is a sealed note: its amount stays a commitment and is shared
              among the custody set, never shown. A filled order is claimed with a proof that names no order, batch or
              price.</li>
            <li><strong>The reserve</strong> — the USDm reserve and the circulating total exist only as Poseidon
              commitments. Each peg operation carries a zero-knowledge proof that value is conserved and the reserve
              stays at least 150% of what it backs. No node ever learns or recomputes a total.</li>
          </ul>
        </div>
        <div class="privacy-col">
          <h3><span class="privacy-pill public">public</span></h3>
          <ul class="privacy-list">
            <li><strong>One clearing price per pair per batch</strong> — the DeFi layer publishes its batch's clearing
              tick, every batch, and never volume, depth, positions or fills.</li>
            <li><strong>Usernames</strong> — an @username you choose to register rides a block as a sign-up signed
              with ML-DSA-65, so every node resolves it the same way. Registering is optional, and it ties the name to
              the key you published with it, nothing more.</li>
            <li><strong>Validator seats</strong> — which keys hold finality seats, and their signed finality votes, are
              public so every node can check them.</li>
            <li><strong>The other chain's side of the bridge</strong> — a deposit to the reserve lands at an address on
              that coin's own chain, held by a threshold of bonded custodians, and it is as visible as that chain
              makes it (a Bitcoin deposit is public on Bitcoin). Minting the USDm for it needs ML-DSA-65 attestations
              from at least two thirds of the bonded custody weight. Bitcoin's own signature scheme is used only at that
              endpoint, on Bitcoin, never on MoneroUSD.</li>
          </ul>
        </div>
      </div>
    </section>

    <section class="card">
      <div class="card-header"><h2>What this explorer cannot show, by construction</h2></div>
      <ul class="privacy-list">
        <li><strong>A balance for an address.</strong> Addresses never reach the chain: there is nothing to look up.</li>
        <li><strong>A history for an address, or who paid whom.</strong> A spend names a nullifier, never the note it spends
          or the notes it pays.</li>
        <li><strong>How busy the chain is.</strong> Every block has the same shape, so the count of real payments is not
          on chain to be shown.</li>
        <li><strong>Trading volume, depth or anyone's position.</strong> Only the clearing price is published.</li>
      </ul>
    </section>
  `;
}
