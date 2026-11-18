#!/bin/bash
cd "$(dirname "$0")" || exit 1
APP="MoneroUSD Wallet.app"
if [ ! -d "$APP" ]; then echo "Put this .command NEXT TO 'MoneroUSD Wallet.app', then double-click it."; read -n1; exit 1; fi
echo "Clearing AirDrop quarantine + launching the wallet…"
xattr -dr com.apple.quarantine "$APP" 2>/dev/null
open "$APP"
echo "Launched. (You can close this window.)"
