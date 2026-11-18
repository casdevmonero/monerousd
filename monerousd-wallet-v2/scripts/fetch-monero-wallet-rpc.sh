#!/bin/bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
#
# §22 6 — RELEASE PACKAGING: put Monero's own `monero-wallet-rpc` inside the app (src-tauri/sidecar/), so a validator's node
# runs its custody wallet with nothing to install and no Monero node (the node points it at onion daemons through its Tor:
# usdmd_node::xmr_supervisor). The archive is Monero's official CLI release; it is used ONLY if its SHA-256 equals the hash
# Monero published for it (getmonero.org/downloads/hashes.txt, read 2026-10-30, v0.18.5.4). Run once per release build.
set -euo pipefail
VER=v0.18.5.4
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  F=monero-mac-armv8-$VER.tar.bz2;   H=d457de7c8a1ad42e3232fdea6d9f9003be9652143fb8f719c1fc906aa6b4917b ;;
  Darwin-x86_64) F=monero-mac-x64-$VER.tar.bz2;     H=9fefa7f5f7ae60fbd8d0ad18842b76c56ed161eca4ffb4f8b5f4800e5033b146 ;;
  Linux-x86_64)  F=monero-linux-x64-$VER.tar.bz2;   H=ba2928962c101b609434bf8c1b43ad59ebe96c5525977284ca599d8bf0f02d10 ;;
  Linux-aarch64) F=monero-linux-armv8-$VER.tar.bz2; H=d20d71e6522b41eb8e549c3425f7f4622c9c9a448fc7147525393fd0a6b59703 ;;
  *) echo "no pinned Monero release for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
curl -fsSL --max-time 600 -o "$WORK/$F" "https://downloads.getmonero.org/cli/$F"
GOT="$(shasum -a 256 "$WORK/$F" | cut -d' ' -f1)"
if [ "$GOT" != "$H" ]; then
  echo "REFUSED: $F hashes to $GOT, Monero published $H" >&2
  exit 1
fi
tar -xjf "$WORK/$F" -C "$WORK"
BIN="$(find "$WORK" -type f -name monero-wallet-rpc | head -1)"
mkdir -p "$HERE/src-tauri/sidecar"
install -m 0755 "$BIN" "$HERE/src-tauri/sidecar/monero-wallet-rpc"
echo "sidecar/monero-wallet-rpc from $F (sha256 $H)"
