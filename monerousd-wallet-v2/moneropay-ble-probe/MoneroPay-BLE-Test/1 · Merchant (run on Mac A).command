#!/bin/bash
cd "$(dirname "$0")" || exit 1
BIN="./MoneroPay BLE Probe.app/Contents/MacOS/moneropay-ble-probe"
OUT="/tmp/mpay_merchant_gui.out"
xattr -dr com.apple.quarantine "MoneroPay BLE Probe.app" 2>/dev/null
: > "$OUT"
echo "MoneroPay - MERCHANT (Mac A). Click Allow on the Bluetooth prompt, then leave this open."
echo "-----------------------------------------------------------------------------------"
"$BIN" merchant "MoneroPay charge \$5.00" 2>&1 | tee "$OUT"
