#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# publish-checkpoint-records.sh — DNSSEC-signed checkpoint publisher.
#
# Reads the local USDmd's chain state and produces TXT-record
# update batches for the operator's DNS zone. After a successful
# manual zone-update step, every wallet on the network picks up the
# new checkpoint floor on its next daemon restart (no wallet binary
# update needed).
#
# How daemons consume these:
#   src/checkpoints/checkpoints.cpp::load_checkpoints_from_dns()
#   queries `checkpoints.monerousd.org` (and the mirror
#   `checkpoints2.monerousd.org`) for TXT records matching
#   "<height>:<block_hash_hex>". Each record is added as a hardcoded
#   checkpoint, which:
#     - Prevents chain rewrites below that height (defeats deep
#       reorg attacks).
#     - Lets the daemon SKIP detailed transaction validation for
#       blocks ≤ that height when the block hashes match (the
#       hash chain integrity is already chain-anchored).
#
# What the operator does, end to end:
#   1. Run this script on the release machine.
#   2. It reads the local daemon's get_info → top_block_hash and
#      builds a recommended checkpoint slate (typically the most
#      recent 5 round-thousand heights below the tip, e.g. 120k,
#      121k, 122k, 123k).
#   3. Outputs a `nsupdate` batch + zonefile delta + signed BIND
#      `dnssec-signzone` instructions.
#   4. Operator reviews + applies to the production DNS zone.
#   5. Every wallet picks up the new floor on next daemon restart.
#
# This is intentionally NOT an automated cron job that publishes
# directly to DNS. Checkpoints are CONSENSUS-VISIBLE — a wrong
# checkpoint can split the network. Manual review is the safety
# net. Once the operator has a track record of correct slates,
# automate it.

set -euo pipefail

RPC_HOST="${RPC_HOST:-127.0.0.1}"
RPC_PORT="${RPC_PORT:-17750}"
ZONE_TARGET="${ZONE_TARGET:-checkpoints.monerousd.org}"
ZONE_MIRROR="${ZONE_MIRROR:-checkpoints2.monerousd.org}"
SLATE_BLOCKS_BACK="${SLATE_BLOCKS_BACK:-5}"  # 5 round-thousand heights below tip
ROUND_INTERVAL="${ROUND_INTERVAL:-1000}"     # checkpoint every 1k blocks
OUTPUT="${OUTPUT:-./checkpoint-records.txt}"

# ── Read daemon state ──────────────────────────────────────────────
echo "Querying daemon at $RPC_HOST:$RPC_PORT for current chain state…"
INFO=$(curl -fsSL -m 10 "http://$RPC_HOST:$RPC_PORT/get_info") || {
  echo "ERROR: daemon RPC unreachable at $RPC_HOST:$RPC_PORT" >&2
  exit 2
}
TIP=$(echo "$INFO" | python3 -c "import sys,json; print(json.load(sys.stdin)['height_without_bootstrap'])")
[ -n "$TIP" ] || { echo "ERROR: daemon did not report height_without_bootstrap" >&2; exit 3; }
TIP=$((TIP - 1))  # height of the actual top block (height is count-of-blocks)

echo "Current local tip: height=$TIP"
echo

# ── Build the checkpoint slate ────────────────────────────────────
# Pick the most recent N round-interval heights below the tip,
# leaving ROUND_INTERVAL blocks of headroom under the tip so the
# checkpoint is well past any plausible reorg depth.
declare -a SLATE
LATEST_ROUND=$(( (TIP - ROUND_INTERVAL) / ROUND_INTERVAL * ROUND_INTERVAL ))
for ((i=0; i<SLATE_BLOCKS_BACK; i++)); do
  H=$((LATEST_ROUND - i * ROUND_INTERVAL))
  [ "$H" -le 0 ] && break
  SLATE+=( "$H" )
done

echo "Slate (most recent first):"
printf '  %d\n' "${SLATE[@]}"
echo

# ── Resolve each height to its block hash ─────────────────────────
echo "Resolving block hashes…"
> "$OUTPUT"
echo "; MoneroUSD checkpoint TXT records — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT"
echo "; Apply to zones: $ZONE_TARGET (primary), $ZONE_MIRROR (mirror)" >> "$OUTPUT"
echo "; Daemons consume these via load_checkpoints_from_dns() at startup." >> "$OUTPUT"
echo "" >> "$OUTPUT"
for H in "${SLATE[@]}"; do
  BODY=$(printf '{"jsonrpc":"2.0","id":"0","method":"getblockheaderbyheight","params":{"height":%d}}' "$H")
  HASH=$(curl -fsSL -m 10 -d "$BODY" -H 'content-type: application/json' \
    "http://$RPC_HOST:$RPC_PORT/json_rpc" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['block_header']['hash'])")
  [ -n "$HASH" ] || { echo "ERROR: failed to resolve block at height $H" >&2; exit 4; }
  printf '%s.    600  IN  TXT  "%d:%s"\n' "$ZONE_TARGET" "$H" "$HASH" >> "$OUTPUT"
  printf '%s.   600  IN  TXT  "%d:%s"\n' "$ZONE_MIRROR" "$H" "$HASH" >> "$OUTPUT"
  echo "  height=$H hash=$HASH"
done
echo "" >> "$OUTPUT"
echo "; To apply on a BIND zone with DNSSEC:" >> "$OUTPUT"
echo ";   1. Replace the existing TXT records for $ZONE_TARGET + $ZONE_MIRROR" >> "$OUTPUT"
echo ";      with the entries above." >> "$OUTPUT"
echo ";   2. Re-sign with: dnssec-signzone -o <zone> -k <KSK> -K <key-dir> <zonefile>" >> "$OUTPUT"
echo ";   3. Reload: rndc reload" >> "$OUTPUT"
echo ";   4. Verify external resolvers see the new records:" >> "$OUTPUT"
echo ";        dig +short TXT $ZONE_TARGET" >> "$OUTPUT"

echo
echo "Records written to: $OUTPUT"
echo
echo "REVIEW before applying:"
echo "  1. cross-check at least 2 independent daemons report the same block hash"
echo "     at each checkpoint height (use VPS + edge as the cross-checks)."
echo "  2. then apply the zone update + re-sign with DNSSEC."
