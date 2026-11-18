// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// ecosystem.js — sovereign sites, read from the node's app server beside this page (`/v1/sites`). Chain-directory
// reads (tokens, NFTs, @names, pools) live in lib/chain.js.

import * as ds from './data-source.js';

export async function getSites() {
  try {
    const r = await ds.getSites();
    return { source: 'node', data: Array.isArray(r) ? r : (r?.sites || r?.items || []) };
  } catch (e) {
    return { source: 'offline', data: [], error: e.message };
  }
}
