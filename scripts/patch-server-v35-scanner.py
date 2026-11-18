#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# Idempotently insert the v35 chain-scanner startup block into the deployed
# Ion Swap backend server.js, right after the attestation-monitor start. Safe to
# re-run (no-op if already present). Backs up before writing.
import sys, time, shutil, os

PATH = '/opt/ion-monerousd-org/backend/server.js'
ANCHOR = "catch (e) { console.warn('[ion] attestation monitor start failed:', e.message); }"
BLOCK = """

// PQ-carrier ingestion (HF v35 on-chain envelope) — USDm is PQ-confidential, so
// protocol carriers ride as pq_create_transfer txs whose op payload is in the
// on-chain v35 envelope (tx_extra 0x28). Those PQ-note receives never appear in
// the swap wallet's classic get_transfers, so the monitor above can't see them.
// This scanner walks new blocks and feeds each tx to the SAME processIncomingTx
// -> recoverOnChainOp -> dispatch path (idempotent on tx_hash). Gated on the
// same flag v35-envelope.js honors. See backend/monitor/v35-chain-scanner.js.
if (process.env.ION_V35_ONCHAIN_DECRYPT === '1') {
  try {
    const v35Scanner = await import('./monitor/v35-chain-scanner.js');
    v35Scanner.start();
  } catch (e) { console.warn('[ion] v35 chain-scanner start failed:', e.message); }
}
"""

src = open(PATH, 'r').read()
if 'v35-chain-scanner' in src:
    print('already patched (no-op)')
    sys.exit(0)
if ANCHOR not in src:
    print('ANCHOR NOT FOUND — aborting, no change')
    sys.exit(1)
shutil.copy2(PATH, PATH + '.preV35Scanner-' + time.strftime('%Y%m%d-%H%M%S'))
src = src.replace(ANCHOR, ANCHOR + BLOCK, 1)
open(PATH, 'w').write(src)
print('patched + backed up')
