MoneroUSD Wallet — run on your SECOND Mac (Mac B), the PAYER side of the MoneroPay tap test.

INSTALL (no signing, no account, $0)
1. AirDrop this whole "MoneroPay-Wallet-MacB" folder to Mac B (accept it on Mac B).
2. On Mac B, double-click  "Open MoneroUSD Wallet.command".
   (It clears the AirDrop quarantine flag and opens the wallet. If macOS still asks,
    right-click "MoneroUSD Wallet.app" -> Open -> Open — one time only.)
3. When the wallet asks to use Bluetooth, click Allow.

THE TWO-MAC TAP TEST (two real Bluetooth radios)
- Mac A (this laptop): open the wallet -> USDm Pay / POS -> create a charge (e.g. $5.00).
  The charge auto-advertises over MoneroPay BLE — no setup, it's built in.
- Mac B (this app): open the wallet -> "Create new wallet" (instant fresh PQ seed; no funds
  needed just to RECEIVE the tap) -> the Pay / tap screen ("Hold near the reader") -> hold
  Mac B within a few inches of Mac A.
  Mac B discovers the merchant over the real radio, range-gates on RSSI, runs the ML-KEM
  handshake, and OPENS the sealed charge — showing the amount + merchant to confirm.
That confirm screen appearing on Mac B = the MoneroPay tap crossing two real radios, in the
actual wallet UI. (Approving the payment then broadcasts a real PQ spend when Mac B's wallet
is funded + reachable to the node — that final settlement step is covered separately.)
