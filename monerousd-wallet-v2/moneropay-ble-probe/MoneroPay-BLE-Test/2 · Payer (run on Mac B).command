#!/bin/bash
cd "$(dirname "$0")" || exit 1
BIN="./MoneroPay BLE Probe.app/Contents/MacOS/moneropay-ble-probe"
OUT="/tmp/mpay_payer_gui.out"
xattr -dr com.apple.quarantine "MoneroPay BLE Probe.app" 2>/dev/null
: > "$OUT"
echo "MoneroPay - PAYER (Mac B). Click Allow on the Bluetooth prompt; hold this Mac near Mac A."
echo "-----------------------------------------------------------------------------------"
"$BIN" payer 2>&1 | tee "$OUT"
echo ""
echo "(this window can be closed)"
