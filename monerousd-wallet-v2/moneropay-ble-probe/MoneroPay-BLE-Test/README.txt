MoneroPay — real two-Mac Bluetooth tap test (no signing, no account, $0)

WHAT THIS PROVES: the MoneroPay tap crosses the REAL Bluetooth air between two
separate radios. The tool shares the EXACT code the wallet uses:
  moneropay.rs      (ML-KEM-768 session + sealed-charge AEAD + range gate + framing)
  moneropay_ble.rs  (Core Bluetooth peripheral/central binding)

STEPS
1. AirDrop (or copy) this whole "MoneroPay-BLE-Test" folder to your SECOND Mac.
2. On Mac A: double-click  "1 · Merchant (run on Mac A).command".
   - If macOS says it can't verify the developer: right-click the .command -> Open -> Open.
   - Click "Allow" on the Bluetooth permission prompt. Leave the window open (it advertises).
3. On Mac B: double-click  "2 · Payer (run on Mac B).command".
   - Right-click -> Open the first time if macOS blocks it; click "Allow" for Bluetooth.
   - Keep the two Macs within a few feet.
4. Mac B prints:  "RECEIVED the sealed charge OVER THE AIR: MoneroPay charge $5.00"
   plus the measured RSSI / distance. That is the two-radio tap, end to end.

Why a .app + this folder instead of an App-Store install: macOS lets you run your
own unsigned programs (unlike iOS). Nothing is signed, nothing phones home.
