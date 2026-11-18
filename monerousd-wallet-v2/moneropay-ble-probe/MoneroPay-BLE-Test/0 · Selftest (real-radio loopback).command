#!/bin/bash
cd "$(dirname "$0")" || exit 1
BIN="./MoneroPay BLE Probe.app/Contents/MacOS/moneropay-ble-probe"
OUT="/tmp/mpay_selftest_gui.out"
xattr -dr com.apple.quarantine "MoneroPay BLE Probe.app" 2>/dev/null
: > "$OUT"
echo "MoneroPay - real-radio SELFTEST. Click Allow if macOS asks to use Bluetooth."
echo "-----------------------------------------------------------------------------"
"$BIN" selftest 2>&1 | tee "$OUT"
echo "EXIT=${PIPESTATUS[0]}" | tee -a "$OUT"
echo ""
echo "done - you can close this window."
